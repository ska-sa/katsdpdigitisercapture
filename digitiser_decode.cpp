#include <spead2/recv_udp_pcap.h>
#include <spead2/recv_stream.h>
#include <spead2/recv_ring_stream.h>
#include <spead2/recv_heap.h>
#include <spead2/common_logging.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <memory>
#include <vector>
#include <unordered_set>
#include <limits>
#include <tbb/pipeline.h>
#include <tbb/task_scheduler_init.h>
#include <immintrin.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#if !SPEAD2_USE_PCAP
# error "spead2 was built without pcap support"
#endif

namespace po = boost::program_options;

#ifndef __BYTE_ORDER__
# warning "Unable to detect byte order"
#elif __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
# error "Only little endian is currently supported"
#endif

/* Number of multicast addresses used. It is acceptable if it is a smaller
 * power of two, although it will cause a few packets to be unnecessarily
 * discarded from the front.
 */
static constexpr int MAX_ADDRESSES = 8;

/***************************************************************************/

/* Take buffer of packed 10-bit signed values (big-endian) and return them as 16-bit
 * values.
 */
[[gnu::target("default")]]
static std::vector<std::int16_t> decode_10bit(const std::uint8_t *data, std::size_t length)
{
    std::size_t out_length = length * 8 / 10;
    std::vector<std::int16_t> out;
    out.reserve(out_length);
    std::uint64_t buffer = 0;
    int buffer_bits = 0;
    for (std::size_t i = 0; i < length; i += 4)
    {
        std::uint32_t chunk;
        std::memcpy(&chunk, &data[i], 4);
        chunk = ntohl(chunk);
        buffer = (buffer << 32) | chunk;
        buffer_bits += 32;
        while (buffer_bits >= 10)
        {
            buffer_bits -= 10;
            std::int64_t value = (buffer >> buffer_bits) & 1023;
            // Convert to signed
            if (value & 512)
                value -= 1024;
            out.push_back(value);
        }
    }
    return out;
}

template<int left>
[[gnu::target("avx2")]]
static inline __m256i extr(__m256i in)
{
    static_assert(0 <= left && left <= 22, "left is out of ange");
    if (left)
        return _mm256_srai_epi32(_mm256_slli_epi32(in, left), 22);
    else
        return _mm256_srai_epi32(in, 22);
}

template<int left>
[[gnu::target("avx2")]]
static inline __m256i extr2(__m256i in0, __m256i in1)
{
    static_assert(22 < left && left < 32, "left is out of ange");
    __m256i part = _mm256_srai_epi32(_mm256_slli_epi32(in0, left), 22);
    return _mm256_or_si256(part, _mm256_srli_epi32(in1, 54 - left));
}

/* AVX-2 optimised version of the decoding. It loads 32-bit integers and does
 * shifting to extract the relevant bits. Gather instructions are used to
 * transpose the 32-bit integers on load, so that consecutive 32-bit values are
 * in consecutive registers/variables. To extract a 10-bit field, there are two
 * cases:
 *
 * 1. The 10-bit value is entirely contained in the 32-bit field. This is extracted
 *    by shifting left by some number of bits, then shifting right (with sign
 *    extension). All the unwanted bits fall out the ends.
 * 2. The 10-bit value is split across two 32-bit fields. In this case both fields
 *    need shifting to extract the relevant bits, which are then ORed together. The
 *    second field needs a logical (unsigned) right shift so that it doesn't get
 *    sign extension.
 *
 * Since AVX2 doesn't support scatter instructions, a large part of the
 * implementation is dedicated to transposing the data so that 16-bit outputs
 * that need to be contiguous in memory get placed contiguously in the
 * registers.
 */
[[gnu::target("avx2")]]
static std::vector<std::int16_t> decode_10bit(const std::uint8_t *data, std::size_t length)
{
    std::size_t out_length = length * 8 / 10;
    std::vector<std::int16_t> out(out_length);

    std::size_t blocks = out_length / 128;  // 128 is number of samples per loop iteration
    // shuffle control to swap 32-bit values from big to little endian
    __m256i bswap = _mm256_set_epi32(
        0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203,
        0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203
    );

    /* These pointers are not aligned, which is okay because they're used with
     * instructions that allow unaligned access.
     */
    const std::int32_t *x_ptr = (const std::int32_t *) data;
    __m128i *y_ptr = (__m128i *) out.data();
    // Offsets (in 32-bit words) at which the lanes in gather instructions
    // are loaded.
    __m256i offsets = _mm256_set_epi32(35, 30, 25, 20, 15, 10, 5, 0);

    for (size_t i = 0; i < blocks; i++, x_ptr += 40, y_ptr += 16)
    {
        // Load 32-bit values and convert from big endian to little
        __m256i a0 = _mm256_shuffle_epi8(_mm256_i32gather_epi32(x_ptr + 0, offsets, 4), bswap);
        __m256i a1 = _mm256_shuffle_epi8(_mm256_i32gather_epi32(x_ptr + 1, offsets, 4), bswap);
        __m256i a2 = _mm256_shuffle_epi8(_mm256_i32gather_epi32(x_ptr + 2, offsets, 4), bswap);
        __m256i a3 = _mm256_shuffle_epi8(_mm256_i32gather_epi32(x_ptr + 3, offsets, 4), bswap);
        __m256i a4 = _mm256_shuffle_epi8(_mm256_i32gather_epi32(x_ptr + 4, offsets, 4), bswap);

        /* Extract the 10-bit values. At the end of this operation, each 32-bit
         * element contains a 10-bit value (sign-extended). These operations
         * are easiest to think of as if they were scalar. The different SIMD
         * lanes correspond to different contiguous 160-bit blocks of input.
         */
        __m256i y0 = extr<0>(a0);
        __m256i y1 = extr<10>(a0);
        __m256i y2 = extr<20>(a0);
        __m256i y3 = extr2<30>(a0, a1);
        __m256i y4 = extr<8>(a1);
        __m256i y5 = extr<18>(a1);
        __m256i y6 = extr2<28>(a1, a2);
        __m256i y7 = extr<6>(a2);
        __m256i y8 = extr<16>(a2);
        __m256i y9 = extr2<26>(a2, a3);
        __m256i ya = extr<4>(a3);
        __m256i yb = extr<14>(a3);
        __m256i yc = extr2<24>(a3, a4);
        __m256i yd = extr<2>(a4);
        __m256i ye = extr<12>(a4);
        __m256i yf = extr<22>(a4);

        /* Now the transposition/interleaving starts. The pack/unpack
         * instructions in AVX are weird: they treat each YMM register as two
         * separate 128-bit registers, and the instruction occurs independent
         * on the lower and upper halves. Any descriptions below should thus be
         * treated as applying separately to each half, and the lower halves
         * always jointly contain the first half of the output.
         */

        // Cast down from 32-bit to 16-bit. Each variable yU_V contains
        // all values for U followed by those for V (not interleaved).
        __m256i y0_8 = _mm256_packs_epi32(y0, y8);
        __m256i y1_9 = _mm256_packs_epi32(y1, y9);
        __m256i y2_a = _mm256_packs_epi32(y2, ya);
        __m256i y3_b = _mm256_packs_epi32(y3, yb);
        __m256i y4_c = _mm256_packs_epi32(y4, yc);
        __m256i y5_d = _mm256_packs_epi32(y5, yd);
        __m256i y6_e = _mm256_packs_epi32(y6, ye);
        __m256i y7_f = _mm256_packs_epi32(y7, yf);

        // yUV alternates between values for U and for V
        __m256i y01 = _mm256_unpacklo_epi16(y0_8, y1_9);
        __m256i y23 = _mm256_unpacklo_epi16(y2_a, y3_b);
        __m256i y45 = _mm256_unpacklo_epi16(y4_c, y5_d);
        __m256i y67 = _mm256_unpacklo_epi16(y6_e, y7_f);
        __m256i y89 = _mm256_unpackhi_epi16(y0_8, y1_9);
        __m256i yab = _mm256_unpackhi_epi16(y2_a, y3_b);
        __m256i ycd = _mm256_unpackhi_epi16(y4_c, y5_d);
        __m256i yef = _mm256_unpackhi_epi16(y6_e, y7_f);

        // yABCD_pX is the X'th value containing interleaved A, B, C, and D components.
        __m256i y0123_p0 = _mm256_unpacklo_epi32(y01, y23);
        __m256i y0123_p1 = _mm256_unpackhi_epi32(y01, y23);
        __m256i y4567_p0 = _mm256_unpacklo_epi32(y45, y67);
        __m256i y4567_p1 = _mm256_unpackhi_epi32(y45, y67);
        __m256i y89ab_p0 = _mm256_unpacklo_epi32(y89, yab);
        __m256i y89ab_p1 = _mm256_unpackhi_epi32(y89, yab);
        __m256i ycdef_p0 = _mm256_unpacklo_epi32(ycd, yef);
        __m256i ycdef_p1 = _mm256_unpackhi_epi32(ycd, yef);

        __m256i y01234567_p0 = _mm256_unpacklo_epi64(y0123_p0, y4567_p0);
        __m256i y01234567_p1 = _mm256_unpackhi_epi64(y0123_p0, y4567_p0);
        __m256i y01234567_p2 = _mm256_unpacklo_epi64(y0123_p1, y4567_p1);
        __m256i y01234567_p3 = _mm256_unpackhi_epi64(y0123_p1, y4567_p1);
        __m256i y89abcdef_p0 = _mm256_unpacklo_epi64(y89ab_p0, ycdef_p0);
        __m256i y89abcdef_p1 = _mm256_unpackhi_epi64(y89ab_p0, ycdef_p0);
        __m256i y89abcdef_p2 = _mm256_unpacklo_epi64(y89ab_p1, ycdef_p1);
        __m256i y89abcdef_p3 = _mm256_unpackhi_epi64(y89ab_p1, ycdef_p1);

        /* Write back results. As noted above, the lower halves contain all the
         * data for the first half of the output.
         */
        _mm_storeu_si128(y_ptr + 0x0, _mm256_extracti128_si256(y01234567_p0, 0));
        _mm_storeu_si128(y_ptr + 0x1, _mm256_extracti128_si256(y89abcdef_p0, 0));
        _mm_storeu_si128(y_ptr + 0x2, _mm256_extracti128_si256(y01234567_p1, 0));
        _mm_storeu_si128(y_ptr + 0x3, _mm256_extracti128_si256(y89abcdef_p1, 0));
        _mm_storeu_si128(y_ptr + 0x4, _mm256_extracti128_si256(y01234567_p2, 0));
        _mm_storeu_si128(y_ptr + 0x5, _mm256_extracti128_si256(y89abcdef_p2, 0));
        _mm_storeu_si128(y_ptr + 0x6, _mm256_extracti128_si256(y01234567_p3, 0));
        _mm_storeu_si128(y_ptr + 0x7, _mm256_extracti128_si256(y89abcdef_p3, 0));
        _mm_storeu_si128(y_ptr + 0x8, _mm256_extracti128_si256(y01234567_p0, 1));
        _mm_storeu_si128(y_ptr + 0x9, _mm256_extracti128_si256(y89abcdef_p0, 1));
        _mm_storeu_si128(y_ptr + 0xa, _mm256_extracti128_si256(y01234567_p1, 1));
        _mm_storeu_si128(y_ptr + 0xb, _mm256_extracti128_si256(y89abcdef_p1, 1));
        _mm_storeu_si128(y_ptr + 0xc, _mm256_extracti128_si256(y01234567_p2, 1));
        _mm_storeu_si128(y_ptr + 0xd, _mm256_extracti128_si256(y89abcdef_p2, 1));
        _mm_storeu_si128(y_ptr + 0xe, _mm256_extracti128_si256(y01234567_p3, 1));
        _mm_storeu_si128(y_ptr + 0xf, _mm256_extracti128_si256(y89abcdef_p3, 1));
    }
    return out;
}

/***************************************************************************/

struct options
{
    std::uint64_t max_heaps = std::numeric_limits<std::uint64_t>::max();
    std::string input_file;
    std::string output_file;
};

class heap_info
{
public:
    spead2::recv::heap heap;
    std::uint64_t timestamp = 0;
    const std::uint8_t *data = nullptr;
    std::size_t length = 0;   // length of payload in bytes
    std::size_t samples = 0;  // length in digitiser samples

    explicit heap_info(spead2::recv::heap &&heap);
    heap_info &operator=(spead2::recv::heap &&heap);

    // noncopyable suppresses the default move constructor
    heap_info(heap_info &&) noexcept = default;
    heap_info &operator=(heap_info &&) noexcept = default;

private:
    void update();

    // make noncopyable
    heap_info(const heap_info &) = delete;
    heap_info &operator=(const heap_info &) = delete;
};

heap_info::heap_info(spead2::recv::heap &&heap) : heap(std::move(heap))
{
    update();
}

heap_info &heap_info::operator=(spead2::recv::heap &&heap)
{
    this->heap = std::move(heap);
    update();
    return *this;
}

void heap_info::update()
{
    timestamp = 0;
    data = nullptr;
    length = 0;
    samples = 0;
    for (const auto &item : heap.get_items())
    {
        if (item.id == 0x1600 && item.is_immediate)
            timestamp = item.immediate_value;
        else if (item.id == 0x3300)
        {
            data = item.ptr;
            length = item.length;
            samples = length * 8 / 10;
        }
    }
}

typedef std::vector<heap_info> heap_batch;

class decoded_info
{
public:
    std::uint64_t timestamp;
    std::vector<int16_t> data;

    decoded_info() = default;
    decoded_info(decoded_info &&) noexcept = default;
    decoded_info &operator=(decoded_info &&) noexcept = default;

private:
    // make noncopyable, just to ensure nothing inefficient is being done
    decoded_info(const decoded_info &) = delete;
    decoded_info &operator=(const decoded_info &) = delete;
};

typedef std::vector<decoded_info> decoded_batch;

class loader
{
private:
    spead2::thread_pool thread_pool;
    spead2::recv::ring_stream<> stream;
    // Buffer for heaps that were read while looking for sync, but still need
    // to be processed
    std::deque<heap_info> infoq;
    std::uint64_t max_heaps;
    bool finished = false;

public:
    std::uint64_t n_heaps = 0;
    std::uint64_t first_timestamp = 0;
    std::size_t samples = 0;     // samples per heap

    explicit loader(const options &opts)
        : thread_pool(),
        stream(thread_pool,
               spead2::recv::stream_config().set_max_heaps(2),
               spead2::recv::ring_stream_config().set_heaps(128)),
        max_heaps(opts.max_heaps)
    {
        stream.emplace_reader<spead2::recv::udp_pcap_file_reader>(opts.input_file);

        try
        {
            /* N multicast groups are interleaved, and the multicast
             * subscriptions may have kicked in at different times. Proceed
             * until we have seen data from all of them.
             */
            infoq.emplace_back(stream.pop());
            std::cout << "First timestamp is " << infoq[0].timestamp << '\n';
            std::vector<bool> seen(MAX_ADDRESSES);
            int waiting = MAX_ADDRESSES;
            while (true)
            {
                if (infoq[0].samples != 0)
                {
                    int phase = (infoq[0].timestamp / infoq[0].samples) % MAX_ADDRESSES;
                    if (!seen[phase])
                    {
                        seen[phase] = true;
                        waiting--;
                        if (waiting == 0)
                            break;
                    }
                }
                infoq.pop_front();
                infoq.emplace_back(stream.pop());
            }
            first_timestamp = infoq[0].timestamp;
            samples = infoq[0].samples;
            std::cout << "First synchronised timestamp is " << first_timestamp << '\n';
        }
        catch (spead2::ringbuffer_stopped &)
        {
            throw std::runtime_error("End of stream reached before stream synchronisation");
        }
    }

    // Returns empty batch on reaching the end
    heap_batch next_batch()
    {
        constexpr int batch_size = 32;
        heap_batch batch;
        batch.reserve(batch_size);
        while (!finished && batch.size() < batch_size)
        {
            if (n_heaps >= max_heaps)
            {
                std::cout << "Stopping after " << max_heaps << " heaps\n";
                finished = true;
                break;
            }
            if (infoq.empty())
            {
                try
                {
                    infoq.emplace_back(stream.pop());
                }
                catch (spead2::ringbuffer_stopped &)
                {
                    std::cout << "Stream ended after " << n_heaps << " heaps\n";
                    finished = true;
                    break;
                }
            }
            heap_info info = std::move(infoq[0]);
            infoq.pop_front();
            if (info.samples > 0)   // Skip over non-data heaps e.g. descriptors
            {
                n_heaps++;
                batch.push_back(std::move(info));
            }
        }
        return batch;
    }
};

class writer
{
private:
    std::ofstream out;
    std::uint64_t first_timestamp;
    std::size_t samples;    // samples per heap - must be constant
    std::unordered_set<std::uint64_t> seen;
    std::uint64_t n_elements = 0;

    static constexpr int header_size = 96;

public:
    writer(const std::string &filename, std::uint64_t first_timestamp, std::size_t samples);
    void write(const decoded_info &heap);
    void close();
    void report();
};

constexpr int writer::header_size;

writer::writer(const std::string &filename, std::uint64_t first_timestamp, std::size_t samples)
    : out(filename, std::ios::out | std::ios::binary),
    first_timestamp(first_timestamp),
    samples(samples)
{
    out.exceptions(std::ios::failbit | std::ios::badbit);
    // Make space for the header
    out.seekp(header_size);
}

void writer::write(const decoded_info &heap)
{
    if (heap.timestamp < first_timestamp)
    {
        std::cerr << "Warning: discarding heap with timestamp "
            << heap.timestamp << " which is before start\n";
        return;
    }
    if (heap.data.size() != samples)
    {
        std::cerr << "Warning: discarding heap with " << heap.data.size()
            << " samples, expected " << samples << '\n';
        return;
    }
    if (!seen.insert(heap.timestamp).second)
    {
        std::cerr << "Warning: discarding heap with duplicate timestamp "
            << heap.timestamp << '\n';
        return;
    }
    std::uint64_t position = heap.timestamp - first_timestamp;
    constexpr std::size_t elem_size = sizeof(decltype(heap.data)::value_type);
    out.seekp(header_size + position * elem_size);
    out.write(reinterpret_cast<const char *>(heap.data.data()), heap.data.size() * elem_size);
    seen.insert(heap.timestamp);
    n_elements = std::max(n_elements, position + heap.data.size());
}

void writer::close()
{
    // Write in the header
    out.seekp(0);
    char header_start[10] = "\x93NUMPY\x01\x00";
    header_start[8] = header_size - 10;
    header_start[9] = 0;
    out.write(header_start, 10);
    out << "{'descr': '<i2', 'fortran_order': False, 'shape': ("
        << n_elements << ",) }";
    if (out.tellp() >= header_size)
        throw std::runtime_error("Oops, header was too big for reserved space! File is corrupted!");
    while (out.tellp() < header_size - 1)
        out << ' ';
    out << '\n';
    out.close();
}

void writer::report()
{
    std::uint64_t captured_samples = seen.size() * samples;
    std::uint64_t missing_samples = n_elements - captured_samples;
    double ratio = double(missing_samples) / n_elements;
    std::cout << "Converted " << captured_samples << " samples, "
        << missing_samples << " missing (" << ratio * 100
        << "%), from timestamp " << first_timestamp << '\n';
}

template<typename T>
static po::typed_value<T> *make_opt(T &var)
{
    return po::value<T>(&var)->default_value(var);
}

static void usage(std::ostream &o, const po::options_description &desc)
{
    o << "Usage: digitiser_decode [opts] <input.pcap> <output.npy>\n";
    o << desc;
}

static options parse_options(int argc, char **argv)
{
    options opts;
    po::options_description desc, hidden, all;
    desc.add_options()
        ("heaps", make_opt(opts.max_heaps), "Number of heaps to process [all]")
    ;
    hidden.add_options()
        ("input", make_opt(opts.input_file), "input")
        ("output", make_opt(opts.output_file), "output")
    ;
    all.add(desc);
    all.add(hidden);

    po::positional_options_description positional;
    positional.add("input", 1);
    positional.add("output", 1);
    try
    {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
            .style(po::command_line_style::default_style & ~po::command_line_style::allow_guessing)
            .options(all)
            .positional(positional)
            .run(), vm);
        po::notify(vm);
        if (vm.count("help"))
        {
            usage(std::cout, desc);
            std::exit(0);
        }
        return opts;
    }
    catch (po::error &e)
    {
        std::cerr << e.what() << '\n';
        usage(std::cerr, desc);
        std::exit(2);
    }
}

int main(int argc, char **argv)
{
    options opts = parse_options(argc, argv);
    // Leave 1 core free for decoding the SPEAD stream
    int n_threads = tbb::task_scheduler_init::default_num_threads() - 1;
    if (n_threads < 1)
        n_threads = 1;
    tbb::task_scheduler_init init_tbb(n_threads);

    loader load(opts);
    writer out(opts.output_file, load.first_timestamp, load.samples);

    auto read_filter = [&] (tbb::flow_control &fc) -> std::shared_ptr<heap_batch>
    {
        std::shared_ptr<heap_batch> batch = std::make_shared<heap_batch>(load.next_batch());
        if (batch->empty())
            fc.stop();
        return batch;
    };

    auto decode_filter = [&](std::shared_ptr<heap_batch> batch) -> std::shared_ptr<decoded_batch>
    {
        std::shared_ptr<decoded_batch> out = std::make_shared<decoded_batch>();
        for (const heap_info &info : *batch)
        {
            decoded_info out_info;
            out_info.timestamp = info.timestamp;
            out_info.data = decode_10bit(info.data, info.length);
            out->emplace_back(std::move(out_info));
        }
        return out;
    };

    auto write_filter = [&](std::shared_ptr<decoded_batch> batch)
    {
        for (const decoded_info &decoded : *batch)
            out.write(decoded);
    };

    tbb::parallel_pipeline(16,
        tbb::make_filter<void, std::shared_ptr<heap_batch>>(
            tbb::filter::serial_in_order, read_filter)
        & tbb::make_filter<std::shared_ptr<heap_batch>, std::shared_ptr<decoded_batch>>(
            tbb::filter::parallel, decode_filter)
        & tbb::make_filter<std::shared_ptr<decoded_batch>, void>(
            tbb::filter::serial, write_filter));

    // Write in the header
    out.close();
    std::cout << "Header successfully written\n";

    // Write the timestamp file
    std::ofstream timestamp_file(opts.output_file + ".timestamp");
    timestamp_file.exceptions(std::ios::failbit | std::ios::badbit);
    timestamp_file << load.first_timestamp << '\n';
    timestamp_file.close();
    std::cout << "Timestamp file written\n\n";
    out.report();
    return 0;
}
