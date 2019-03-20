#!/usr/bin/groovy
properties(
        [
            parameters([
                string(name: 'tlpUrl', defaultValue: '', description: 'Link to TLP to use for tests')
            ])
        ])

TARGET=""
TLP_URL=""
MAVEN_SERVER = "https://engci-maven-master.cisco.com/artifactory/"
DEB_VERSION = ''

timestamps {
    try {
        stage('Build') {
            node('fmc-build') {
                checkout scm

                script { config = readYaml(file: './tests_integration/configuration/default.yaml') }
                script { TARGET = config.expressway.exp_hostname1.toString() } //TODO investigate standardising this
                print("Expressway Target: ${TARGET}")

                print('static analysis')
                sh("python setup.py pylint")
                sh("test_environment/run_bandit.sh")

                print('unit test')
                sh("nosetests tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml")

                // Archive unit tests results
                junit allowEmptyResults: true, testResults: 'test-results.xml'

                sh("./build_and_upgrade.sh -c upgrade -v ${BUILD_ID} -t ${TARGET} -w;")
                DEB_VERSION = sh(script: 'dpkg-deb --field debian/_build/c_mgmt.deb Version', returnStdout: true).trim()
                archiveArtifacts('debian/_build/c_mgmt.deb')
                stash(includes: 'debian/_build/c_mgmt.deb', name: 'debian')
            }
        }

        stage('Build TLP') {
            node('fmc-build') {
                checkout scm
                unstash('debian')

                // setup file locations
                debian="c_mgmt.deb"
                private_key="private.pem"

                sh("mv ./debian/_build/c_mgmt.deb ${debian}")
                folder_path = sh(script: 'pwd', returnStdout: true).trim()
                sshagent(credentials: ['LYS-GIT']) {
                    sh("git archive --remote=git@lys-git.cisco.com:projects/system-trunk-os HEAD:linux/tblinbase/files ${private_key} | tar -x")
                }

                withCredentials([file(credentialsId: 'SWIMS', variable: 'swims_ticket')]) {
                    sh("./build_and_upgrade.sh -c build_tlp ${folder_path}/${debian} ${folder_path}/${private_key} ${swims_ticket}")
                }

                archiveArtifacts('_build/c_mgmt/*')
                uploadArtifactsToMaven('_build/c_mgmt/*.tlp')
                tlp_name = sh(script: 'ls _build/c_mgmt/*.tlp', returnStdout: true).trim()
                TLP_URL = "${MAVEN_SERVER}team-cafe-release/sqbu-pipeline/tlps/${tlp_name}"
                stash(includes: '_build/c_mgmt/*.tlp', name: 'tlp')
            }
        }

        stage('system test'){
            node('fmc-build') {
                sh('python -m unittest discover tests_integration/ "*_test.py"')
            }
        }

        // Only allow Deploy Stages from the master
        if (env.BRANCH_NAME == 'master') {

            stage('Release tests') {
                runOldPipeline(TLP_URL)
            }

            stage('Deploy to Latest') {
                node('fmc-build') {
                    // Setup provisioning data
                    build('team/management-connector/deploy_files/provisioning_json_latest')
                }
                // TODO - Run deployAndIntTest
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

// TODO: DELETE THIS ONCE TTM IS NO MORE
def runOldPipeline(String tlpUrl) {
    node('fmc-build') {
        withCredentials([usernamePassword(credentialsId: 'cafefusion.gen', usernameVariable: 'cafe_user', passwordVariable: 'cafe_pass')]) {
            job = "Jobs/bitbucket-pipelines/CAFETOOLS/auto/cafe-tools/master"
            parameters = "-p tlpUrl=${tlpUrl}"
            echo "Triggering old pipeline on https://engci-private-gpk.cisco.com/jenkins/"
            sh("rm -rf jenkins-cli.jar*")
            sh("wget -q https://engci-private-gpk.cisco.com/jenkins/citg-expressway/jnlpJars/jenkins-cli.jar")
            sh("java -jar jenkins-cli.jar -auth ${cafe_user}:${cafe_pass} -s https://engci-private-gpk.cisco.com/jenkins/citg-expressway/ build '${job}' ${parameters} -s -v")
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
        try {
            // Loop through for each environment
            environments.each {
                // 'it' is the implicit param for each element in the list
                def environment = it
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

def uploadArtifactsToMaven(String pattern) {
    maven_repo = "team-cafe-release/sqbu-pipeline/tlps/"

    upload_spec = """{
        "files": [
            {
                "pattern": "${pattern}",
                "target": "${maven_repo}",
                "flat": "true"
            }
        ]
    }"""

    withCredentials([usernamePassword(credentialsId: 'cafefusion.gen-maven', usernameVariable: 'maven_username', passwordVariable: 'maven_password')]) {
        // publish artifacts to maven
        def server = Artifactory.newServer(url: MAVEN_SERVER, username: maven_username, password: maven_password)

        server.upload(upload_spec)
    }
}
