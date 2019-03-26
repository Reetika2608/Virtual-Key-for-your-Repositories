/**
 *  Common Utility methods to be used across multiple Jenkinsfiles
 */

MAVEN_SERVER = "https://engci-maven-master.cisco.com/artifactory/"

def uploadArtifactsToMaven(String file_path, String dir_path) {
    maven_repo = "team-cafe-release/sqbu-pipeline/${dir_path}"

    withCredentials([usernamePassword(credentialsId: 'cafefusion.gen-maven', usernameVariable: 'maven_username', passwordVariable: 'maven_password')]) {
        print("Uploading artifacts to maven; src: ${file_path} destination: ${MAVEN_SERVER}${maven_repo}")
        sh("curl -i -X PUT -u ${maven_username}:${maven_password} -T ${file_path} ${MAVEN_SERVER}${maven_repo}")
    }
}

return this