FROM --platform=linux/amd64 ubuntu:focal

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive

ENV DPDK_DIR             /opt/dpdk
ENV PCAPPLUSPLUS_DIR     /opt/PcapPlusPlus
ENV CONDA_DIR            /opt/conda
ENV Torch_DIR            /opt/pytorch

ENV CMAKE_VERSION        v3.25.2
ENV DPDK_VERSION         v21.11
ENV PCAPPLUSPLUS_VERSION v22.11
# ENV DPDK_VERSION v18.02
# ENV PCAPPLUSPLUS_VERSION v19.04

WORKDIR /opt

RUN apt-get update

RUN apt-get -y install \
	man \
	build-essential \
	wget \
	curl \
	git \
	vim \
	tmux \
	iputils-ping \
	iproute2 \
	net-tools \
	tcpreplay \
	iperf \
	psmisc \
	htop \
	gdb \
	ninja-build \
	meson \
	python3-pyelftools \
	libpcap-dev \
	libnuma-dev \
	python3-pip \
	libssl-dev \
	libarmadillo-dev \
	libstb-dev \
	libboost-test-dev \
	libboost-serialization-dev \
	libgflags-dev \
	binutils-dev \
	python3-pandas \
	python3-numpy \
	cython \
	python-setuptools \
	libensmallen-dev \
	libcereal-dev \
	python3-pip \
	pkg-config \
	libmlpack-dev

##########################
#                        #
#         CMake          #
#                        #
##########################

RUN git clone \
	--depth 1 \
	--branch $CMAKE_VERSION \
	https://github.com/Kitware/CMake

RUN cd CMake && \
	./bootstrap && \
	make -j && \
	make install

##########################
#                        #
#          DPDK          #
#                        #
##########################

RUN git clone \
	--depth 1 \
	--branch $DPDK_VERSION \
	https://github.com/DPDK/dpdk.git \
	$DPDK_DIR

RUN cd $DPDK_DIR && \
	meson build && \
	cd build && \
	ninja && \
	ninja install && \
	ldconfig

ENV RTE_SDK $DPDK_DIR

##########################
#                        #
#    LibPcapPlusPlus     #
#                        #
##########################

RUN git clone \
	--depth 1 \
	--branch $PCAPPLUSPLUS_VERSION \
	https://github.com/seladb/PcapPlusPlus.git \
	$PCAPPLUSPLUS_DIR

RUN cd $PCAPPLUSPLUS_DIR && \
	./configure-linux.sh --dpdk --dpdk-home $DPDK_DIR && \
	make -j libs && \
	make install

##########################
#                        #
#        PyTorch         #
#                        #
##########################

RUN git clone \
	--recursive \
	https://github.com/pytorch/pytorch \
	$Torch_DIR

RUN cd $Torch_DIR && \
	git submodule sync && \
	git submodule update --init --recursive && \
	pip3 install -r requirements.txt && \
	python3 setup.py develop

COPY . /opt/whisper
WORKDIR /opt/whisper

RUN mkdir build && \
	cd build && \
	cmake -G Ninja .. && \
	ninja
