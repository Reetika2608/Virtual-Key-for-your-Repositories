#!/usr/bin/groovy

TARGET=""

pipeline {
    agent {
        docker {
            image 'fmc-build'
            args '--mount type=bind,source="$HOME/",target="/management-connector"'
        }
    }

    stages {

        stage('Configure') {
            steps {
                // Need to install the readYaml plugin, and ensure it's available on SQBU
                script { config = readYaml (file: './tests_integration/configuration/default.yaml') }
                script { TARGET = config.expressway.exp_hostname1.toString() }
                echo "Expressway Target: ${TARGET}"
            }
        }

        stage('static analysis'){
            steps{
                sh "python setup.py pylint"
                sh "test_environment/run_bandit.sh"
            }
        }

        stage('unit test'){
             steps{
                sh "nosetests tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml"
            }
            post{
                always{
                    // Archive unit tests results
                    junit allowEmptyResults: true,
                        testResults: 'test-results.xml'
                }
            }
        }

        stage('build'){
            steps{
                sh "./build_and_upgrade.sh -c upgrade -v ${BUILD_ID} -t ${TARGET} -w;"
            }
        }

        stage('system test'){
            steps{
                sh 'python -m unittest discover tests_integration/ "*_test.py"'
            }
        }

    }
    post{
        success{
            archiveArtifacts artifacts: 'debian/_build/c_mgmt.deb'
        }
    }
}
