pipeline {
   agent any

   tools {
      // Install the Maven version configured as "M3" and add it to the path.
      maven "maven-name-in-global-settings"
   }

   stages {
      stage('JAR Build') {
         steps {
            // Get some code from a GitHub repository
            git 'https://github.com/NadiraFathima/Spring-Boot-Server.git'

            // Run Maven on a Unix agent.
            sh "mvn -Dmaven.test.failure.ignore=true clean package"

            // To run Maven on a Windows agent, use
            // bat "mvn -Dmaven.test.failure.ignore=true clean package"
         }

         post {
            // If Maven was able to run the tests, even if some of the test
            // failed, record the test results and archive the jar file.
            success {
               archiveArtifacts 'target/*.jar'
            }
            
         }
      }
      stage('Docker Build') {
         steps {
            sh "docker build -t my-image ."
         }
           
      }
   }
}
