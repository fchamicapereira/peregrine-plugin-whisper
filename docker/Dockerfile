FROM --platform=linux/amd64 ubuntu:focal

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Lisbon

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV DPDK_DIR            /opt/dpdk
ENV PCAPPLUSPLUS_DIR    /opt/PcapPlusPlus
ENV CONDA_DIR           /opt/conda
ENV PYTORCH_DIR         /opt/pytorch

ENV CMAKE_VERSION			v3.25.2
ENV DPDK_VERSION			v21.11
ENV PCAPPLUSPLUS_VERSION	v22.11
ENV PYTORCH_VERSION			release/1.9

WORKDIR /opt

RUN apt update && apt -y install \
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
	libmlpack-dev \
	fzf \
	shellcheck

RUN dpkg-reconfigure --frontend noninteractive tzdata

# CMake

RUN git clone \
	--depth 1 \
	--branch $CMAKE_VERSION \
	https://github.com/Kitware/CMake

RUN cd CMake && \
	./bootstrap && \
	make -j && \
	make install

# DPDK

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

# LibPcapPlusPlus

RUN git clone \
	--depth 1 \
	--branch $PCAPPLUSPLUS_VERSION \
	https://github.com/seladb/PcapPlusPlus.git \
	$PCAPPLUSPLUS_DIR

RUN cd $PCAPPLUSPLUS_DIR && \
	./configure-linux.sh --dpdk --dpdk-home $DPDK_DIR && \
	make -j libs && \
	make install

# PyTorch

RUN git clone \
	--branch $PYTORCH_VERSION \
	--recursive \
	https://github.com/pytorch/pytorch \
	$PYTORCH_DIR

RUN cd $PYTORCH_DIR && \
	git submodule sync && \
	git submodule update --init --recursive && \
	pip3 install -r requirements.txt && \
	python3 setup.py develop

CMD [ "/bin/bash", "-l"]
