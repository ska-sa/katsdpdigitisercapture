#!groovy

@Library('katsdpjenkins') _
katsdp.killOldJobs()

katsdp.setDependencies(['ska-sa/katsdpdockerbase/master'])
katsdp.standardBuild(python2: false, python3: false, push_external: true)
katsdp.mail('sdpdev+katsdpdigitisercapture@ska.ac.za')
