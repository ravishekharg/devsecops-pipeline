// The same gates as the GitHub workflow: every stage is a script in ci/, so the CI system only
// orders them, holds credentials and keeps the reports. Needs an agent with docker, git, bash
// and GNU tar (tools run as pinned containers; see ci/lib.sh for why source is copied in, not
// bind-mounted: this Jenkins talks to the host's Docker daemon from inside a container).
pipeline {
  agent any
  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
    timeout(time: 45, unit: 'MINUTES')
  }
  parameters {
    booleanParam(name: 'SIGN_AND_ADMIT', defaultValue: false,
      description: 'Also sign the image and run the Kyverno admission test (needs kind/helm/kubectl on the agent and the cosign-key-b64 / cosign-pub-b64 credentials)')
  }
  environment {
    IMAGE = "notes-api:${env.BUILD_NUMBER}"
    OUT = "${env.WORKSPACE}/reports"
  }
  stages {
    stage('Secrets')       { steps { sh 'bash ci/10-secrets.sh' } }
    stage('SAST')          { steps { sh 'bash ci/20-sast.sh' } }
    stage('Dependencies')  { steps { sh 'bash ci/30-dependencies.sh' } }
    stage('Dockerfile')    { steps { sh 'bash ci/40-dockerfile.sh' } }
    stage('Manifests')     { steps { sh 'bash ci/50-manifests.sh' } }
    stage('Test & build')  { steps { sh 'bash ci/60-test-build.sh' } }
    stage('Image scan')    { steps { sh 'bash ci/70-image-scan.sh' } }
    stage('SBOM')          { steps { sh 'bash ci/80-sbom.sh' } }
    stage('DAST')          { steps { sh 'bash ci/90-dast.sh' } }
    stage('Sign & admit') {
      when { expression { params.SIGN_AND_ADMIT } }
      steps {
        withCredentials([string(credentialsId: 'cosign-key-b64', variable: 'COSIGN_KEY_B64'),
                         string(credentialsId: 'cosign-pub-b64', variable: 'COSIGN_PUB_B64'),
                         string(credentialsId: 'cosign-password', variable: 'COSIGN_PASSWORD')]) {
          sh 'bash ci/95-sign-and-admit.sh'
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/*.sarif, reports/sbom.*.json, reports/zap/zap.*', allowEmptyArchive: true
      sh 'docker rmi -f "$IMAGE" >/dev/null 2>&1 || true; rm -f reports/image.tar'
    }
  }
}
