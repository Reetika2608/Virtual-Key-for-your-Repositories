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

timestamps {
    stage('Build') {
        node('fmc-build') {
            // Need to install the readYaml plugin, and ensure it's available on SQBU
            script { config = readYaml(file: './tests_integration/configuration/default.yaml') }
            script { TARGET = config.expressway.exp_hostname1.toString() }
            echo "Expressway Target: ${TARGET}"

            print('static analysis')
            sh "python setup.py pylint"
            sh "test_environment/run_bandit.sh"

            print('unit test')
            sh "nosetests tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml"

            // Archive unit tests results
            junit allowEmptyResults: true, testResults: 'test-results.xml'

            sh "./build_and_upgrade.sh -c upgrade -v ${BUILD_ID} -t ${TARGET} -w;"
            archiveArtifacts artifacts: 'debian/_build/c_mgmt.deb'
        }
    }

    stage('Build TLP') {
        node('fmc-build') {
            if (!params.tlpUrl) {
            } else {
                TLP_URL = params.tlpUrl
                sh("rm -rf *.tlp")
                sh "wget -q ${params.tlpUrl}"

                archiveArtifacts('*.tlp')
                tlp_name = sh(script: 'ls *.tlp', returnStdout: true).trim()
                uploadArtifactsToMaven('*.tlp')
                TLP_URL = "${MAVEN_SERVER}team-cafe-release/sqbu-pipeline/tlps/${tlp_name}"
            }
        }
    }

    stage('system test'){
        node('fmc-build') {
            sh 'python -m unittest discover tests_integration/ "*_test.py"'
        }
    }

    stage('Release tests') {
        print(TLP_URL)
        //runOldPipeline(TLP_URL)
    }
    always {
        cleanWs()
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
