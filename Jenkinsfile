#!/usr/bin/groovy

pipeline {
    agent { dockerfile true }
    stages {
        stage('clean') {
            steps {
                sh 'python setup.py clean'
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
