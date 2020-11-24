#!/usr/bin/groovy
@Library('sparkPipeline') _

pipelineProperties(name: 'management-connector',
                   numToKeep: 20,
                   integration: [
                   runSecurityScans: true])

DEB_VERSION = ''
TLP_FILE = ''
def pythonBuilder = 'containers.cisco.com/hybridmanagement/fmc-builder-base-ssh-slave:latest'
def builderName = 'local-spark-pythonbuilder-fmc'

timestamps {
    try {

        stage('Build') {

            node('SPARK_BUILDER') {
                try {
                      checkout scm

                      def container_builder = docker.image(pythonBuilder).run("-t --name $builderName")
                      sh("docker cp ./ ${builderName}:/home/jenkins")
                      sh("docker exec ${builderName} pwd")
                      sh("docker exec ${builderName} ls -ltr")

                      print('static analysis')
                      sh("docker exec ${builderName} python lint.py pylint")

                      // Archive bandit tests results
                      sh("docker exec ${builderName} bandit -r src/ -x src/unittests,src/base_platform -f xml -o bandit-results.xml")
                      sh("docker cp ${builderName}:/home/jenkins/bandit-results.xml ./")
                      junit allowEmptyResults: true, testResults: 'bandit-results.xml'

                      // Archive unit tests results
                      sh("docker exec ${builderName} nosetests tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml")
                      sh("docker cp ${builderName}:/home/jenkins/test-results.xml ./")
                      junit allowEmptyResults: true, testResults: 'test-results.xml'

                      sh("docker exec ${builderName} ./build_and_upgrade.sh -c build -v ${BUILD_ID};")

                      sh("docker cp ${builderName}:/home/jenkins/debian/_build/c_mgmt.deb ./")

                      print("check for debian")
                      DEB_VERSION = sh(script: 'dpkg-deb --field ./c_mgmt.deb Version', returnStdout: true).trim()

                      archiveArtifacts('c_mgmt.deb')
                      stash(includes: 'c_mgmt.deb', name: 'debian')

                      //archive library.yml file
                      archiveArtifacts('library.yml')
                      stash(includes: 'library.yml', name: 'library')

                      //archive pem file
                      //To-Do: The key to be removed once the lys-git.cisco.com is whitelisted
                      archiveArtifacts('private.pem')
                      stash(includes: 'private.pem', name: 'key')

                      container_builder.stop()
                } catch (err) {
                      error('Deploy failed')
                } finally {
                      deleteDir()
                      cleanWs()
                      sh returnStatus: true, script: """
                      # Remove any previous support containers
                      ERRANT_CONTAINERS=\$(docker ps -aq --filter "name=${builderName}")
                      [[ -n \$ERRANT_CONTAINERS ]] && docker rm --force \$ERRANT_CONTAINERS || true
                      """
                }
            }
        }

        stage('Build TLP') {
            checkpoint("We have a debian. Let's create a TLP.")
            node('SPARK_BUILDER') {
                checkout scm

                unstash('debian')
                unstash('key')
                debian = "c_mgmt.deb"
                private_key = "private.pem"
                swims_ticket = "FMC.tic.RELEASE"
                folder_path = pwd()
                sh("ls -ltr")

                print("Gather required components - debian, key and swims ticket.")

                print("Package debian into a TLP.")
                withCredentials([string(credentialsId: 'fmc-swims', variable: 'swims_content')]) {
                    sh("echo ${swims_content}")
                    sh("echo ${swims_content} >> ${swims_ticket}")
                    sh("./build_and_upgrade.sh -c build_tlp ${folder_path}/${debian} ${folder_path}/${private_key} ${folder_path}/${swims_ticket}")
                    sh("rm -rf ${folder_path}/${swims_ticket}")
                }

                // Archive the Swims log file at this stage
                archiveArtifacts('_build/c_mgmt/log.txt')

                print("Set TLP name for subsequent stages.")
                TLP_FILE = "c_mgmt_${DEB_VERSION}.tlp"
                sh("mv _build/c_mgmt/${TLP_FILE} ${TLP_FILE}")

                utils = load('jenkins/methods/utils.groovy')
                maven_tlp_dir = 'tlps/'
                utils.uploadArtifactsToMaven("${TLP_FILE}", maven_tlp_dir)

                stash(includes: "${TLP_FILE}", name: 'tlp')
                archiveArtifacts("${TLP_FILE}")
            }
        }

        stage('System Tests') {
            checkpoint("We have a tlp. Let's run system tests.")
            node('SPARK_BUILDER') {
                try {

                      checkout scm

                      def container_builder = docker.image(pythonBuilder).run("-t --name $builderName")
                      sh("docker cp ./ ${builderName}:/home/jenkins")
                      sh("docker exec ${builderName} pwd")

                      def logsDir = "logs/" + new Date().format("YYYYMMdd-HHmmss")
                      def pythonLogsDir = "./"  + logsDir + "/"
                      print("directory set for logs")
                      def resources = getResources('./jenkins/test_resources/bangalore_resources.yaml')

                      unstash('tlp')
                      sh("docker cp ${TLP_FILE} ${builderName}:/home/jenkins")
                      sleep(10)

                      try {
                          parallel (
                              'Unregistered tests': {
                                    lock(resource: resources.exp_hostname_unreg_1) {
                                        print("Installing .tlp for Unregistered tests")
                                        sh("docker cp ${TLP_FILE} ${builderName}:/home/jenkins")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_1} -w ${TLP_FILE}")
                                        print("Performing unregistered tests")
                                        sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                         -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                         -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                         -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                         -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                         -e LOGS_DIR=${pythonLogsDir} \
                                         ${builderName} nosetests --with-xunit --xunit-file=unregistered-test-results.xml tests_integration/unregistered_tests""".stripIndent())

                                         sh("docker cp ${builderName}:/home/jenkins/unregistered-test-results.xml ./")

                                         junit allowEmptyResults: true, testResults: 'unregistered-test-results.xml'

                                    }
                              },
                              'API registration tests': {
                                    lock(resource: resources.exp_hostname_unreg_1) {
                                        print("Installing .tlp for API registration tests")
                                        sh("docker cp ${TLP_FILE} ${builderName}:/home/jenkins")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_1} -w ${TLP_FILE}")
                                        print("Performing API tests")

                                        withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                            sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                             -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                             -e ORG_ID=${config.org.org_id} \
                                             -e ORG_ADMIN_USER=${org_admin_user} \
                                             -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             -e LOGS_DIR=${pythonLogsDir} \
                                             ${builderName} nosetests --with-xunit --xunit-file=api-based-test-results.xml tests_integration/api_based_tests""".stripIndent())

                                             sh("docker cp ${builderName}:/home/jenkins/api-based-test-results.xml ./")

                                             junit allowEmptyResults: true, testResults: 'api-based-test-results.xml'
                                        }

                                    }
                              },
                              'UI registration tests': {
                                    lock(resource: resources.exp_hostname_unreg_2) {
                                        print("Installing .tlp for UI registration tests")
                                        sh("docker cp ${TLP_FILE} ${builderName}:/home/jenkins")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_2} -w ${TLP_FILE}")

                                        print("Performing UI tests")
                                        withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {

                                            try {
                                                sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                                 -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                                 -e ORG_ID=${config.org.org_id} \
                                                 -e ORG_ADMIN_USER=${org_admin_user} \
                                                 -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                 -e LOGS_DIR=${pythonLogsDir} \
                                                 ${builderName} nosetests --with-xunit --xunit-file=ui-based-register-test-results.xml tests_integration/ui_based_tests/basic_register_test.py""".stripIndent())

                                                 sh("docker cp ${builderName}:/home/jenkins/ui-based-register-test-results.xml ./")

                                                 junit allowEmptyResults: true, testResults: 'ui-based-register-test-results.xml'
                                            }
                                            finally {
                                                sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                                 -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                                 -e ORG_ID=${config.org.org_id} \
                                                 -e ORG_ADMIN_USER=${org_admin_user} \
                                                 -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                 ${builderName} ./build_and_upgrade.sh -c clean_exp -t ${resources.exp_hostname_unreg_2}""".stripIndent())
                                            }
                                        }
                                    }
                              },
                              'Registered tests': {
                                    lock(resource: resources.exp_hostname_reg_1) {
                                        print("Installing .tlp for registered tests")
                                        sh("docker cp ${TLP_FILE} ${builderName}:/home/jenkins")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_reg_1} -w ${TLP_FILE}")
                                        print("Performing registered tests")
                                        withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                            sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_reg_1} \
                                             -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                             -e ORG_ID=${config.org.org_id} \
                                             -e ORG_ADMIN_USER=${org_admin_user} \
                                             -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             -e LOGS_DIR=${pythonLogsDir} \
                                             ${builderName} nosetests --with-xunit --xunit-file=registered-test-results.xml tests_integration/registered_tests""".stripIndent())

                                             sh("docker cp ${builderName}:/home/jenkins/registered-test-results.xml ./")

                                             junit allowEmptyResults: true, testResults: 'registered-test-results.xml'
                                        }

                                    }
                              },
                              'Clustered tests': {
                                    // The plugin is unable to handle locking of multiple resources
                                    // (without using label, which would require admin access or a custom Jenkins job).
                                    // We therefore lock only the primary cluster node, even though we use both
                                    lock(resource: resources.exp_hostname_unreg_cluster_node_1) {
                                        print("Installing .tlp on node 1 for Clustered tests")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_cluster_node_1} -w ${TLP_FILE}")
                                        print("Installing .tlp on node 2 for Clustered tests")
                                        sh("docker exec ${builderName} ./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_cluster_node_2} -w ${TLP_FILE}")

                                        print("Performing cluster tests")
                                        withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                            sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_cluster_node_1} \
                                             -e EXP_HOSTNAME_SECONDARY=${resources.exp_hostname_unreg_cluster_node_2} \
                                             -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                             -e ORG_ID=${config.org.org_id} \
                                             -e ORG_ADMIN_USER=${org_admin_user} \
                                             -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             -e LOGS_DIR=${pythonLogsDir} \
                                             ${builderName} nosetests --with-xunit --xunit-file=cluster-test-results.xml tests_integration/cluster_tests/""".stripIndent())

                                             sh("docker cp ${builderName}:/home/jenkins/cluster-test-results.xml ./")

                                             junit allowEmptyResults: true, testResults: 'cluster-test-results.xml'
                                        }

                                    }
                              }
                          )
                      } finally {
                            sh("docker cp ${builderName}:/home/jenkins/logs ./")
                            archiveArtifacts artifacts: "${logsDir}/*.*", allowEmptyArchive: true
                      }

                      container_builder.stop()
                } catch (err) {
                      error('Deploy failed')
                } finally {
                      deleteDir()
                      cleanWs()
                      sh returnStatus: true, script: """
                      # Remove any previous support containers
                      ERRANT_CONTAINERS=\$(docker ps -aq --filter "name=${builderName}")
                      [[ -n \$ERRANT_CONTAINERS ]] && docker rm --force \$ERRANT_CONTAINERS || true
                      """
                }
            }
        }

        // Only allow Deploy Stages from the master
        if (env.BRANCH_NAME == 'master') {

            stage('Deploy to Latest') {
                checkpoint("Deploy to latest")
                node('SPARK_BUILDER') {
                    // Setup provisioning data
                    def provisioning_json_job_url = 'team/management-connector/deploy_files/provisioning_json_latest'
                    def provisioning_build = build(provisioning_json_job_url)
                    copyArtifacts(filter: 'latest_provisioning_targeted.txt',
                            fingerprintArtifacts: true,
                            flatten: true,
                            projectName: provisioning_json_job_url,
                            selector: specific("${provisioning_build.number}"))

                    copyArtifacts(filter: 'latest_provisioning.txt',
                            fingerprintArtifacts: true,
                            flatten: true,
                            projectName: provisioning_json_job_url,
                            selector: specific("${provisioning_build.number}"))

                    copyArtifacts(filter: 'library.yml',
                            fingerprintArtifacts: true,
                            flatten: true,
                            projectName: provisioning_json_job_url,
                            selector: specific("${provisioning_build.number}"))

                    // Publish latest_provisioning_targeted.txt to maven
                    utils = load('jenkins/methods/utils.groovy')
                    maven_json_dir = 'provisioning/'
                    utils.uploadArtifactsToMaven('latest_provisioning_targeted.txt', maven_json_dir)
                    utils.uploadArtifactsToMaven('latest_provisioning.txt', maven_json_dir)

                    withCredentials([usernamePassword(credentialsId: 'cafefusion.gen.job.executor', usernameVariable: 'username', passwordVariable: 'token')]) {
                        sparkPipeline.triggerRemoteJob([],
                                'https://sqbu-jenkins.wbx2.com/support/',
                                'cafefusion.gen.job.executor',
                                'platform/tlp-deploy/tlp-deploy-management-connector-integration-latest',
                                "management_connector#${BUILD_NUMBER}")
                    }

                    // TODO - Remove call to sqbu, and replace with local INT pipeline
                    // Kicking Old INT pipeline
                     withCredentials([usernamePassword(credentialsId: 'cafefusion.gen.job.executor', usernameVariable: 'username', passwordVariable: 'token')]) {
                        sparkPipeline.triggerRemoteJob([],
                                'https://sqbu-jenkins.wbx2.com/support/',
                                'cafefusion.gen.job.executor',
                                'platform/tlp-deploy/tlp-deploy-management-connector-production-latest',
                                "management_connector#${BUILD_NUMBER}")
                    }
                }
            }
            stage('Tests against latest') {
                checkpoint("Tests against latest")
                node('SPARK_BUILDER') {
                    checkout scm

                    try {

                        def container_builder = docker.image(pythonBuilder).run("-t --name $builderName")
                        sh("docker cp ./ ${builderName}:/home/jenkins")
                        sh("docker exec ${builderName} pwd")

                        def logsDir = "logs/" + new Date().format("YYYYMMdd-HHmmss")
                        def pythonLogsDir = "./"  + logsDir + "/"
                        print("directory set for logs")
                        def resources = getResources('./jenkins/test_resources/bangalore_resources.yaml')


                        parallel(
                            'Bootstrap & cert test': {
                                lock(resource: resources.exp_hostname_unreg_1) {
                                    print("Performing bootstrap & cert tests")
                                    withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                        try {
                                            sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                                 -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                                 -e ORG_ID=${config.org.org_id} \
                                                 -e ORG_ADMIN_USER=${org_admin_user} \
                                                 -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                 -e LOGS_DIR=${pythonLogsDir} \
                                                 -e BROKEN_CERTS_LOCATION=./tests_against_latest/all_cas_removed.pem \
                                                 ${builderName} nosetests --with-xunit --xunit-file=bootstrap-latest-test-results.xml tests_against_latest/basic_bootstrap_test.py""".stripIndent())

                                                 sh("docker cp ${builderName}:/home/jenkins/bootstrap-latest-test-results.xml ./")

                                                 junit allowEmptyResults: true, testResults: 'bootstrap-latest-test-results.xml'
                                        } finally {
                                            sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                                 -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                                 -e ORG_ID=${config.org.org_id} \
                                                 -e ORG_ADMIN_USER=${org_admin_user} \
                                                 -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                 ${builderName} ./build_and_upgrade.sh -c clean_exp -t ${resources.exp_hostname_unreg_1}""".stripIndent())
                                        }
                                    }
                                }
                            },
                            'Upgrade test': {
                                lock(resource: resources.exp_hostname_reg_2) {
                                    print("Performing upgrade tests")
                                    withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                        sh("""docker exec -e EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_reg_2} \
                                             -e EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             -e EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             -e EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             -e EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             -e CONFIG_FILE=jenkins/test_resources/bangalore_config.yaml \
                                             -e ORG_ID=${config.org.org_id} \
                                             -e ORG_ADMIN_USER=${org_admin_user} \
                                             -e ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             -e LOGS_DIR=${pythonLogsDir} \
                                             -e EXPECTED_VERSION=${DEB_VERSION} \
                                             ${builderName} nosetests --with-xunit --xunit-file=bootstrap-latest-test-results.xml tests_against_latest/upgrade_test.py""".stripIndent())

                                             sh("docker cp ${builderName}:/home/jenkins/upgrade-latest-test-results.xml ./")

                                             junit allowEmptyResults: true, testResults: 'upgrade-latest-test-results.xml'
                                    }
                                }
                            }
                        )
                    } finally {
                        archiveArtifacts artifacts: "${logsDir}/*.*", allowEmptyArchive: true
                        deleteDir()
                        cleanWs()
                        sh returnStatus: true, script: """
                        # Remove any previous support containers
                        ERRANT_CONTAINERS=\$(docker ps -aq --filter "name=${builderName}")
                        [[ -n \$ERRANT_CONTAINERS ]] && docker rm --force \$ERRANT_CONTAINERS || true
                        """
                    }
                }
            }

            stage('Deploy to Alpha') {
                // Generate and Deploy Provisioning Data to FMS
                deploy('alpha', ['production', 'cfe'])
            }

            stage('Deploy to Beta') {
                // Generate and Deploy Provisioning Data to FMS
                deploy('beta', ['integration', 'production', 'cfe'])
            }

            stage('Deploy to Stable') {
                // Generate and Deploy Provisioning Data to FMS
                deploy('stable', ['integration', 'production', 'cfe'])
            }

            // This stage publishes the tested debian to the Expressway "wood" build
            // which will get injected in the Expressway image
            // This stage is moved  after stable so that the Expressway "wood" build always has a stable c_mgmt debian which is thoroughly tested.
            stage('Deploy to wood repo') {
                checkpoint("Deploy to Expressway repo")
                node('SPARK_BUILDER') {
                    // Get the stashed debian from the previous stages
                    unstash('debian')
                    sshagent(credentials: ['cafefusion.gen-sshNoPass']) {
                        sh('scp -o StrictHostKeyChecking=no c_mgmt.deb cafefusion.gen@nfstool.rd.cisco.com:/export/tandberg/system/releases/c_mgmt/master/c_mgmt.deb')
                    }
                }
            }
        }
    }
    finally {
        node('SPARK_BUILDER') {
            print('Cleaning ws')
            cleanWs()
        }
    }
}

/********************************************************************************/
/*                          Pipeline Functions                                  */
/********************************************************************************/

// TODO: Export targeted deploy and INT pipeline tests from SQBU to SQBU-01

def deploy(String release, List<String> environments) {
    checkpoint("Deploy to ${release}")
    timeout(time: 20, unit: 'MINUTES') {
        input "Deploy ${DEB_VERSION} to ${release} release channel?"
    }
    node('SPARK_BUILDER') {
        // Setup provisioning data
        build("team/management-connector/deploy_files/provisioning_json_${release}")

        // Deploy provisioning Data
        def environment = ""
        try {
            // Loop through for each environment
            environments.each {
                // 'it' is the implicit param for each element in the list
                environment = it
                def deploy_job = "platform/tlp-deploy/tlp-deploy-management-connector-${environment}-${release}"

                if ((release == "stable") && (environment == "cfe")) {
                    deploy_job = "platform/tlp-deploy/tlp-deploy-management-connector-${environment}"
                }
                withCredentials([usernamePassword(credentialsId: 'cafefusion.gen.job.executor', usernameVariable: 'username', passwordVariable: 'token')]) {
                    sparkPipeline.triggerRemoteJob([],
                            'https://sqbu-jenkins.wbx2.com/support/',
                            'cafefusion.gen.job.executor',
                            deploy_job,
                            "management_connector#${BUILD_NUMBER}")
                }
            }
        } catch (Exception e) {
            if (environment == "cfe"){
                // Allow a failure in CFE deploy to be skipped
                timeout(time: 5, unit: 'MINUTES') {
                    input("Deploy to ${release}: CFE failed do you want to skip and continue?")
                }
            } else {
                // Propagate failure for NON-CFE environments
                throw e
            }
        }
    }
}

def getResources(String resourceFile) {
    config = readYaml(file: resourceFile)
    expresswayGroups = config.expressway.resource_groups

    print("Found ${expresswayGroups.size()} sets of test resources")

    // We keep a separate set of resources for the master branch, in order to prevent PRs from blocking a master build
    if (isMasterBranch() || expresswayGroups.size() == 1) { // If we only have one set of Expressways, we'll have to use that one
        resources = expresswayGroups[0]
    } else if (isPullRequest()) { // If we have multiple Expressway groups, split them among PRs
        PRNumber = env.BRANCH_NAME.reverse().take(1).toInteger()
        resources = expresswayGroups[1 + (PRNumber % (expresswayGroups.size() - 1))]
    } else {
        print("*** Warning: Testing with \"PR-1\" testbed even though I am not a pull request!")
        resources = expresswayGroups[1]
    }

    return resources
}