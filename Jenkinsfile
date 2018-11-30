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
                sh "nosetests ni/tests/managementconnector/ --verbose --with-xunit --xunit-file=test-reports/results.xml"
            }
            post{
                always{
                    // Archive unit tests results
                    junit allowEmptyResults: true,
                        testResults: 'test-reports/results.xml'
                }
            }
        }
        stage('build'){
            steps{
                sh(script: """
                        chmod +x build.sh;
                        ./build.sh;
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
