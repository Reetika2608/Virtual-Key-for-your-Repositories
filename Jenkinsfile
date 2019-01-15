#!/usr/bin/groovy

pipeline {
    agent { dockerfile true }
    stages {
        stage('clean') {
            steps {
                sh 'python setup.py clean'
            }
        }
        stage('unit test'){
             steps{
                dir("test_environment/stubs/"){
                    sh "python setup.py install"
                }
                sh "nosetests ni/tests/managementconnector/ --verbose --with-xunit --xunit-file=test-results.xml"
            }
            post{
                always{
                    // Archive unit tests results
                    junit allowEmptyResults: true,
                        testResults: 'test-results.xml'
                }
            }
        }
        stage('static analysis'){
            steps{
                sh "python setup.py pylint"
                sh "test_environment/run_bandit.sh"
            }
        }
        stage('build'){
            steps{
                sh(script: """
                        chmod +x build_and_upgrade.sh;
                        ./build_and_upgrade.sh -c build;
                    """.trim())
            }
        }
    }
    post{
        success{
            archiveArtifacts artifacts: 'debian/_build/c_mgmt.deb'
        }
    }
}
