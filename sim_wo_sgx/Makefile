######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g -pg
else
	SGX_COMMON_CFLAGS += -O2
endif

Crypto_Library_Name := sgx_tcrypto

######## App Settings ########

App_C_Files := $(wildcard app/*.c)
App_Include_Paths := -I./app_lib -I./shared_lib

App_Compile_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_Compile_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_Compile_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_Compile_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS)

App_Wo_SGX := rs_wo_sgx

######## Library Settings ########

Shared_Lib_C_Files := $(wildcard shared_lib/*.c)
Shared_Lib_Objects := $(Shared_Lib_C_Files:.c=.o)

App_Lib_C_Files := $(wildcard app_lib/*.c)
App_Lib_Objects := $(App_Lib_C_Files:.c=.o)

######## ########

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

#ifeq ($(SGX_MODE), HW)
#ifneq ($(SGX_DEBUG), 1)
#ifneq ($(SGX_PRERELEASE), 1)
#Build_Mode = HW_RELEASE
#endif
#endif
#endif

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Wo_SGX)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the enclaves (enclave.so) first with your signing keys before you run the $(App_W_SGX) $(App_Wo_SGX) to launch and access the enclave."
	@echo "To sign the enclaves use the following commands:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key> -enclave enclave.so -out <$(Enclave_Name)> -config enclave/enclave.config.xml"
	@echo "You can also sign the enclaves using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Wo_SGX)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

######## Library Objects ########

app_lib/%.o: app_lib/%.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

shared_lib/%.o: shared_lib/%.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

######## App Objects ########
app/rs_wo_sgx.o: app/rs_wo_sgx.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/sim.wosgx.o: app/sim.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Wo_SGX): app/sim.wosgx.o app/rs_wo_sgx.o $(App_Lib_Objects) $(Shared_Lib_Objects)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Clean ########
.PHONY: clean

clean:
	@rm -rf $(App_Wo_SGX) *.so *.a app/*.o shared_lib/*.o app_lib/*.o
