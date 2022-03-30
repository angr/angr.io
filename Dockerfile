FROM ubuntu:20.04
RUN DEBIAN_FRONTEND=noninteractive \
	apt-get update \
 && apt-get install -qy hugo python3-pip python3-venv
