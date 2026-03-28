pipeline {
    agent any
 
    environment {
        PROJECT_ID = "project-0d52e6a6-157d-44b0-86f"
        REGION = "us-central1"
 
        REPO = "vapt"
        IMAGE = "vapt-app"
 
        DEPLOYMENT = "vapt-app"
        CONTAINER = "vapt-app"
        NAMESPACE = "production"
 
        GCP_CREDENTIALS = "gcp-sa-key"
    }
 
    stages {
 
        stage('Checkout') {
            steps {
                git branch: 'production',
                credentialsId: 'azure-creds',
                url: 'https://frindia2@dev.azure.com/frindia2/maximus/_git/pt-automation-admin' 
            }
        }
 
        stage('Set Tag') {
            steps {
                script {
                    env.TAG = "gc${BUILD_NUMBER}"   // 🔥 NOT v1 anymore
                }
            }
        }
 
        stage('Auth to GCP') {
            steps {
                withCredentials([file(credentialsId: GCP_CREDENTIALS, variable: 'GOOGLE_APPLICATION_CREDENTIALS')]) {
                    sh '''
                    gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
                    gcloud auth configure-docker $REGION-docker.pkg.dev -q
                    '''
                }
            }
        }
 
        stage('Build Image') {
            steps {
                sh '''
                docker build -t $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$IMAGE:$TAG .
                '''
            }
        }
 
        stage('Push Image') {
            steps {
                sh '''
                docker push $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$IMAGE:$TAG
                '''
            }
        }
 
        stage('Deploy to GKE') {
            steps {
                sh '''
                kubectl set image deployment/$DEPLOYMENT \
                $CONTAINER=$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$IMAGE:$TAG \
                -n $NAMESPACE
                '''
            }
        }
 
        stage('Verify Rollout') {
            steps {
                sh '''
                kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=120s
                '''
            }
        }
 
        stage('Rollout History') {
            steps {
                sh '''
                kubectl rollout history deployment/$DEPLOYMENT -n $NAMESPACE
                '''
            }
        }
 
        stage('Health Check') {
            steps {
                sh '''
                kubectl get pods -n $NAMESPACE
                '''
            }
        }
    }
 
    post {
        failure {
            echo "❌ Deployment failed. Rolling back..."
 
            sh '''
            kubectl rollout undo deployment/$DEPLOYMENT -n $NAMESPACE
            '''
        }
 
        success {
            echo "✅ VAPT deployed: $IMAGE:$TAG"
        }
    }
}