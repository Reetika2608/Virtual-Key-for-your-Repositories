/**
 *  Common Utility methods to be used across multiple Jenkinsfiles
 */

def uploadArtifactsToMaven(String pattern, String dir_path) {
    maven_repo = "team-cafe-release/sqbu-pipeline/${dir_path}"

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

return this