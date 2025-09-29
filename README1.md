Pipeline Parameters

DOCKERHUB\_USER: Docker Hub username (default: vivekgshan)



STOP\_CONTAINERS: Option to stop and remove running containers (yes or no)



REMOVE\_IMAGES: Option to remove existing Docker images (yes or no)



GIT\_URL: The Git repository URL (default: your packet-analyzer repo)



GIT\_BRANCH: Git branch to checkout (default: Docker-features-Suhanson)



Environment Variables

Credentials for Docker Hub login are injected securely.



The Docker image tag is set to latest.



Pipeline Stages

1\. Checkout

Clones the specified Git branch from the repository.



2\. Docker Login

Logs in to Docker Hub using stored Jenkins credentials.



3\. Stop Containers (Conditional)

If chosen, stops and forcibly removes running containers related to the services (ui-service, analyzer-service, etc.) as well as database containers.



4\. Remove Images (Conditional)

If chosen, deletes Docker images linked to your Docker Hub namespace and related images like pgadmin and postgres:15.



5\. Build \& Push Images

Builds Docker images for each microservice (capture-service, analyzer-service, parser-service, persistor-service, and ui-service), tags with latest, and pushes to Docker Hub.



6\. Deploy with Docker Compose

Pulls the latest images and starts containers in detached mode, cleaning up orphaned containers.



Post Actions

Logs out of Docker Hub at the end of the pipeline to keep credentials secure.



Usage

Make sure your Jenkins has Docker installed and configured.



Add Docker Hub credentials to Jenkins and name them dockerhub-cred.



Trigger the pipeline with appropriate parameters:



Select whether to stop containers or remove images



Specify Git repository URL and branch if different from defaults



Monitor the pipeline for successful image build, push, and deployment.



This pipeline ensures your microservices are regularly built, updated on Docker Hub, and deployed consistently using Docker Compose, all managed seamlessly through Jenkins.

