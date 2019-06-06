#!/usr/bin/groovy
@Library('sparkPipeline') _

properties([
        // number of builds to keep
        buildDiscarder(logRotator(numToKeepStr: '20')),
])

DEB_VERSION = ''
TLP_FILE = ''

timestamps {
    try {
        stage('Build') {
            node('fmc-build') {
                checkout scm

                print('static analysis')
                sh("python setup.py pylint")
                sh("bandit -r src/ -x src/unittests,src/base_platform -f xml -o bandit-results.xml")

                // Archive bandit tests results
                junit allowEmptyResults: true, testResults: 'bandit-results.xml'

                print('unit test')
                sh("nosetests tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml")

                // Archive unit tests results
                junit allowEmptyResults: true, testResults: 'test-results.xml'

                sh("./build_and_upgrade.sh -c build -v ${BUILD_ID};")
                DEB_VERSION = sh(script: 'dpkg-deb --field debian/_build/c_mgmt.deb Version', returnStdout: true).trim()

                sh("mv ./debian/_build/c_mgmt.deb c_mgmt.deb")
                archiveArtifacts('c_mgmt.deb')
                stash(includes: 'c_mgmt.deb', name: 'debian')
            }
        }

        stage('Build TLP') {
            checkpoint("We have a debian. Let's create a TLP.")
            node('fmc-build') {
                checkout scm
                unstash('debian')

                // setup file locations
                debian = "c_mgmt.deb"
                private_key = "private.pem"
                swims_ticket = "FMC.tic.RELEASE"
                folder_path = pwd()

                print("Gather required components - debian, key and swims ticket.")
                sshagent(credentials: ['cafefusion.gen-sshNoPass']) {
                    try {
                        sh("git archive --remote=git@lys-git.cisco.com:projects/system-trunk-os HEAD:linux/tblinbase/files ${private_key} | tar -x")
                    }
                    catch (e) {
                        println("Initial checkout failed. Has the crate node upgraded? Retrying without host key verification.")
                        sh("ssh -o StrictHostKeyChecking=no -T git@lys-git.cisco.com")
                        sh("git archive --remote=git@lys-git.cisco.com:projects/system-trunk-os HEAD:linux/tblinbase/files ${private_key} | tar -x")
                    }
                }

                print("Package debian into a TLP.")
                withCredentials([string(credentialsId: 'fmc-swims', variable: 'swims_content')]) {
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

        stage('System tests') {
            checkpoint("We have a tlp. Let's run system tests.")
            node('fmc-build') {
                checkout scm
                unstash('tlp')

                logsDir = "logs/" + new Date().format("YYYYMMdd-HHmmss")
                pythonLogsDir = "./"  + logsDir + "/"
                resources = getResources('./jenkins/test_resources/lysaker_resources.yaml')

                try {
                    parallel (
                        'Unregistered tests': {
                            lock(resource: resources.exp_hostname_unreg_1) {
                                print("Installing .tlp...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_1} -w ${TLP_FILE}")
                                print("Performing unregistered tests")
                                sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                 EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                 EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                 EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                 EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                 LOGS_DIR=${pythonLogsDir} \
                                 nosetests --with-xunit --xunit-file=unregistered-test-results.xml tests_integration/unregistered_tests""".stripIndent())

                                junit allowEmptyResults: true, testResults: 'unregistered-test-results.xml'
                            }
                         },
                        'API registration tests': {
                            lock(resource: resources.exp_hostname_unreg_1) {
                                print("Installing .tlp...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_1} -w ${TLP_FILE}")
                                print("Performing API tests")

                                withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                    sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                     EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                     EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                     EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                     EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                     CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                     ORG_ID=${config.org.org_id} \
                                     ORG_ADMIN_USER=${org_admin_user} \
                                     ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                     LOGS_DIR=${pythonLogsDir} \
                                    nosetests --with-xunit --xunit-file=api-based-test-results.xml tests_integration/api_based_tests""".stripIndent())
                                }

                                junit allowEmptyResults: true, testResults: 'api-based-test-results.xml'
                            }
                        },
                        'UI registration tests': {
                            lock(resource: resources.exp_hostname_unreg_2) {
                                print("Installing .tlp...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_2} -w ${TLP_FILE}")

                                print("Performing UI tests")
                                withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                    try {
                                        sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                             EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                             ORG_ID=${config.org.org_id} \
                                             ORG_ADMIN_USER=${org_admin_user} \
                                             ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             LOGS_DIR=${pythonLogsDir} \
                                            nosetests --with-xunit --xunit-file=ui-based-deregister-test-results.xml tests_integration/ui_based_tests/basic_deregister_test.py""".stripIndent())
                                        junit allowEmptyResults: true, testResults: 'ui-based-deregister-test-results.xml'
                                    }
                                    finally {
                                        sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                             EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                             ORG_ID=${config.org.org_id} \
                                             ORG_ADMIN_USER=${org_admin_user} \
                                             ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                            ./build_and_upgrade.sh -c clean_exp -t ${resources.exp_hostname_unreg_2}""".stripIndent())
                                    }

                                    try {
                                        sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                             EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                             ORG_ID=${config.org.org_id} \
                                             ORG_ADMIN_USER=${org_admin_user} \
                                             ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                             LOGS_DIR=${pythonLogsDir} \
                                            nosetests --with-xunit --xunit-file=ui-based-register-test-results.xml tests_integration/ui_based_tests/basic_register_test.py""".stripIndent())
                                        junit allowEmptyResults: true, testResults: 'ui-based-register-test-results.xml'
                                    }
                                    finally {
                                        sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_2} \
                                             EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                             EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                             EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                             EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                             CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                             ORG_ID=${config.org.org_id} \
                                             ORG_ADMIN_USER=${org_admin_user} \
                                             ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                            ./build_and_upgrade.sh -c clean_exp -t ${resources.exp_hostname_unreg_2}""".stripIndent())
                                    }
                                }
                            }
                        },
                        'Registered tests': {
                            lock(resource: resources.exp_hostname_reg_1) {
                                print("Installing .tlp...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_reg_1} -w ${TLP_FILE} ")
                                print("Performing registered tests")
                                withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                    sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_reg_1} \
                                     EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                     EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                     EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                     EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                     CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                     ORG_ID=${config.org.org_id} \
                                     ORG_ADMIN_USER=${org_admin_user} \
                                     ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                     LOGS_DIR=${pythonLogsDir} \
                                     nosetests --with-xunit --xunit-file=registered-test-results.xml tests_integration/registered_tests""".stripIndent())
                                }

                                junit allowEmptyResults: true, testResults: 'registered-test-results.xml'
                            }
                        },
                        'Clustered tests': {
                            // The plugin is unable to handle locking of multiple resources
                            // (without using label, which would require admin access or a custom Jenkins job).
                            // We therefore lock only the primary cluster node, even though we use both
                            lock(resource: resources.exp_hostname_unreg_cluster_node_1) {
                                print("Installing .tlp on node 1...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_cluster_node_1} -w ${TLP_FILE}")
                                print("Installing .tlp on node 2...")
                                sh("./build_and_upgrade.sh -c install_prebuilt -t ${resources.exp_hostname_unreg_cluster_node_2} -w ${TLP_FILE}")

                                print("Performing cluster tests")
                                withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                    sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_cluster_node_1} \
                                     EXP_HOSTNAME_SECONDARY=${resources.exp_hostname_unreg_cluster_node_2} \
                                     EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                     EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                     EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                     EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                     CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                     ORG_ID=${config.org.org_id} \
                                     ORG_ADMIN_USER=${org_admin_user} \
                                     ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                     LOGS_DIR=${pythonLogsDir} \
                                    nosetests --with-xunit --xunit-file=cluster-test-results.xml tests_integration/cluster_tests/""".stripIndent())
                                }

                                junit allowEmptyResults: true, testResults: 'cluster-test-results.xml'
                            }
                        }
                    )
                } finally {
                    archiveArtifacts artifacts: "${logsDir}/*.*", allowEmptyArchive: true
                }
            }
        }

        // Only allow Deploy Stages from the master
        if (env.BRANCH_NAME == 'master') {

            stage('Deploy to Latest') {
                checkpoint("Deploy to latest")
                node('fmc-build') {
                    // Setup provisioning data
                    def provisioning_json_job_url = 'team/management-connector/deploy_files/provisioning_json_latest'
                    def provisioning_build = build(provisioning_json_job_url)
                    copyArtifacts(filter: 'latest_provisioning_targeted.txt',
                            fingerprintArtifacts: true,
                            flatten: true,
                            projectName: provisioning_json_job_url,
                            selector: specific("${provisioning_build.number}"))

                    // Publish latest_provisioning_targeted.txt to maven
                    utils = load('jenkins/methods/utils.groovy')
                    maven_json_dir = 'provisioning/'
                    utils.uploadArtifactsToMaven('latest_provisioning_targeted.txt', maven_json_dir)

                    build('platform/tlp-deploy/tlp-deploy-management-connector-integration-latest')

                    // TODO - Remove call to sqbu, and replace with local INT pipeline
                    // Kicking Old INT pipeline
                    runOldIntPipeline()
                }
            }

            stage('Tests against latest') {
                checkpoint("Tests against latest")
                node('fmc-build') {
                    checkout scm

                    try {
                        logsDir = "logs/" + new Date().format("YYYYMMdd-HHmmss")
                        pythonLogsDir = "./"  + logsDir + "/"
                        resources = getResources('./jenkins/test_resources/lysaker_resources.yaml')

                        parallel(
                            'Bootstrap & cert test': {
                                lock(resource: resources.exp_hostname_unreg_1) {
                                    print("Performing bootstrap & cert tests")
                                    withCredentials([usernamePassword(credentialsId: config.org.org_admin_credentials_id, usernameVariable: 'org_admin_user', passwordVariable: 'org_admin_pass')]) {
                                        try {
                                            sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                                 EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                                 ORG_ID=${config.org.org_id} \
                                                 ORG_ADMIN_USER=${org_admin_user} \
                                                 ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                 LOGS_DIR=${pythonLogsDir} \
                                                 BROKEN_CERTS_LOCATION=./tests_against_latest/all_cas_removed.pem \
                                                nosetests --with-xunit --xunit-file=bootstrap-latest-test-results.xml tests_against_latest/basic_bootstrap_test.py""".stripIndent())
                                            junit allowEmptyResults: true, testResults: 'bootstrap-latest-test-results.xml'
                                        } finally {
                                            sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_unreg_1} \
                                                 EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                                 EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                                 EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                                 EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                                 CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                                 ORG_ID=${config.org.org_id} \
                                                 ORG_ADMIN_USER=${org_admin_user} \
                                                 ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                                ./build_and_upgrade.sh -c clean_exp -t ${resources.exp_hostname_unreg_1}""".stripIndent())
                                        }
                                    }
                                }
                            },
                            'Upgrade test': {
                                lock(resource: resources.exp_hostname_reg_2) {
                                    print("Performing upgrade tests")
                                    sh("""EXP_HOSTNAME_PRIMARY=${resources.exp_hostname_reg_2} \
                                         EXP_ADMIN_USER=${config.expressway.exp_admin_user} \
                                         EXP_ADMIN_PASS=${config.expressway.exp_admin_pass} \
                                         EXP_ROOT_USER=${config.expressway.exp_root_user} \
                                         EXP_ROOT_PASS=${config.expressway.exp_root_pass} \
                                         CONFIG_FILE=jenkins/test_resources/lysaker_config.yaml \
                                         ORG_ID=${config.org.org_id} \
                                         ORG_ADMIN_USER=${org_admin_user} \
                                         ORG_ADMIN_PASSWORD=${org_admin_pass} \
                                         LOGS_DIR=${pythonLogsDir} \
                                         EXPECTED_VERSION=${DEB_VERSION} \
                                        nosetests --with-xunit --xunit-file=bootstrap-latest-test-results.xml tests_against_latest/upgrade_test.py""".stripIndent())
                                    junit allowEmptyResults: true, testResults: 'upgrade-latest-test-results.xml'
                                }
                            }
                        )
                    } finally {
                        archiveArtifacts artifacts: "${logsDir}/*.*", allowEmptyArchive: true
                    }
                }
            }

            // This stage publishes the tested debian to the Expressway "wood" build
            // which will get injected in the Expressway image
            stage('Deploy to wood repo') {
                checkpoint("Deploy to Expressway repo")
                node('fmc-build') {
                    // Get the stashed debian from the previous stages
                    unstash('debian')
                    sshagent(credentials: ['cafefusion.gen-sshNoPass']) {
                        sh('scp -o StrictHostKeyChecking=no c_mgmt.deb cafefusion.gen@nfstool.rd.cisco.com:/export/tandberg/system/releases/c_mgmt/master/c_mgmt.deb')
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
        }
    }
    finally {
        node('fmc-build') {
            print('Cleaning ws')
            cleanWs()
        }
    }
}

/********************************************************************************/
/*                          Pipeline Functions                                  */
/********************************************************************************/

// TODO: Export targeted deploy and INT pipeline tests from SQBU to SQBU-01
def runOldIntPipeline() {
    node('fmc-build') {
        def job = "team/mgmt-connector/fusion-mgt-connector-pipeline-release-channels"

        withCredentials([sshUserPrivateKey(credentialsId: "cafefusion.gen-ssh", keyFileVariable: 'priv_key')]) {
            sh("ssh -p 2022 -o StrictHostKeyChecking=no -i ${priv_key} cafefusion.gen@sqbu-jenkins.cisco.com build '${job}'")
        }
    }
}

def deploy(String release, List<String> environments) {
    checkpoint("Deploy to ${release}")
    timeout(time: 20, unit: 'MINUTES') {
        input "Deploy ${DEB_VERSION} to ${release} release channel?"
    }
    node('fmc-build') {
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
                build(deploy_job)
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
