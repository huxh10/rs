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
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

Crypto_Library_Name := sgx_tcrypto

######## Library Settings ########

Trust_Share_C_Files := $(wildcard trusted_share_code/*.c)
Trust_Share_C_Objects := $(Trust_Share_C_Files:.c=.o)
#Trust_Share_Include_Paths := -I$(SGX_SDK)/include -I./lib
Trust_Share_Include_Paths := -I$(SGX_SDK)/include -nostdinc -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I./lib
Trust_Share_Compile_Flags := $(SGX_COMMON_CFLAGS) -fvisibility=hidden -fpie -fstack-protector $(Trust_Share_Include_Paths)

Trust_Agent_Lib_Name := trusted_agent_code.a
Trust_Agent_C_Files := $(wildcard trusted_agent_code/*.c)
Trust_Agent_C_Objects := $(Trust_Agent_C_Files:.c=.o)
Trust_Agent_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I./trusted_share_code -I./lib
Trust_Agent_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Trust_Agent_Include_Paths)

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Enclave_C_Files_0 := $(wildcard enclave0/*.c)
Enclave_C_Files_1 := $(wildcard enclave1/*.c)
Enclave_C_Files_2 := $(wildcard enclave2/*.c)
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I./trusted_share_code -I./trusted_agent_code -I./lib

Enclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0

Enclave_C_Objects_0 := $(Enclave_C_Files_0:.c=.o)
Enclave_C_Objects_1 := $(Enclave_C_Files_1:.c=.o)
Enclave_C_Objects_2 := $(Enclave_C_Files_2:.c=.o)

Enclave_Name_0 := libenclave0.so
Enclave_Name_1 := libenclave1.so
Enclave_Name_2 := libenclave2.so

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_C_Files := $(wildcard app/*.c)
App_Include_Paths := -I$(SGX_SDK)/include -I./lib -I./trusted_share_code

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

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread -lrt

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Lib_Files := $(wildcard lib/*.c)
App_Lib_Objects := $(App_Lib_Files:.c=.o)

App_C_Objects := $(App_C_Files:.c=.o)
App_Name := rs

######## AS Settings ########

AS_C_Files := $(wildcard as/*.c)
AS_Include_Paths := -I$(SGX_SDK)/include -I./lib -I./trusted_share_code

AS_Compile_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(AS_Include_Paths)
AS_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -L$(CURDIR)/as/libcrypto_utils \
	-Wl,--start-group -l$(Crypto_Library_Name) -lsgx_read_rand -lrdrand -Wl,--end-group

AS_C_Objects := $(AS_C_Files:.c=.o)

AS_Name := as/as

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
all: $(Trust_Agent_Lib_Name) enclave0.so enclave1.so enclave2.so $(App_Name) $(AS_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the enclaves (enclave0.so, enclave1.so, enclave2.so) first with your signing keys before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclaves use the following commands:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key0> -enclave enclave0.so -out <$(Enclave_Name_0)> -config enclave0/enclave0.config.xml"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key1> -enclave enclave1.so -out <$(Enclave_Name_1)> -config enclave1/enclave1.config.xml"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key2> -enclave enclave2.so -out <$(Enclave_Name_2)> -config enclave2/enclave2.config.xml"
	@echo "You can also sign the enclaves using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Trust_Agent_Lib_Name) $(Enclave_Name_0) $(Enclave_Name_1) $(Enclave_Name_2) $(App_Name) $(AS_Name)
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

.PHONY: as_only

as_only: $(AS_Name)

######## Library Objects ########

trusted_share_code/%.o: trusted_share_code/%.c
	@$(CC) $(Trust_Share_Compile_Flags) -c $< -o $@
	@echo "CC   <= $<"

## Agent
trusted_agent_code/%.o: trusted_agent_code/%.c
	@$(CC) $(Trust_Agent_Compile_Flags) -c $< -o $@
	@echo "CC   <= $<"

$(Trust_Agent_Lib_Name): $(Trust_Agent_C_Objects) $(Trust_Share_C_Objects)
	@$(AR) rcs $@ $^
	@echo "GEN  =>  $@"

######## App Objects ########
enclave0/enclave0_u.c enclave0/enclave0_u.h: $(SGX_EDGER8R) enclave0/enclave0.edl
	@cd enclave0 && $(SGX_EDGER8R) --use-prefix --untrusted ../enclave0/enclave0.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

app/enclave0_u.o: enclave0/enclave0_u.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave1/enclave1_u.c enclave1/enclave1_u.h: $(SGX_EDGER8R) enclave1/enclave1.edl
	@cd enclave1 && $(SGX_EDGER8R) --use-prefix --untrusted ../enclave1/enclave1.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

app/enclave1_u.o: enclave1/enclave1_u.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave2/enclave2_u.c enclave2/enclave2_u.h: $(SGX_EDGER8R) enclave2/enclave2.edl
	@cd enclave2 && $(SGX_EDGER8R) --use-prefix --untrusted ../enclave2/enclave2.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

app/enclave2_u.o: enclave2/enclave2_u.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

lib/%.o: lib/%.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app/%.o: app/%.c
	@$(CC) $(App_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(App_Name): app/enclave0_u.o app/enclave1_u.o app/enclave2_u.o $(App_C_Objects) $(App_Lib_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## AS Objects ########

as/%.o: as/%.c
	@$(CC) $(AS_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(AS_Name): $(AS_C_Objects) $(App_Lib_Objects) $(Trust_Share_C_Objects)
	@$(CC) $^ -o $@ $(AS_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

## agent
enclave0/enclave0_t.c enclave0/enclave0_t.h: $(SGX_EDGER8R) enclave0/enclave0.edl
	@cd enclave0 && $(SGX_EDGER8R) --use-prefix --trusted ../enclave0/enclave0.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave0/%.o: enclave0/%.c
	@$(CC) -nostdinc $(Enclave_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

enclave0.so: enclave0/enclave0_t.o $(Enclave_C_Objects_0) $(Trust_Agent_Lib_Name)
	@$(CC) enclave0/enclave0_t.o $(Enclave_C_Objects_0) $(Trust_Agent_Lib_Name) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Name_0): enclave0.so
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave0/enclave0_private.pem -enclave enclave0.so -out $@ -config enclave0/enclave0.config.xml
	@echo "SIGN =>  $@"

enclave1/enclave1_t.c enclave1/enclave1_t.h: $(SGX_EDGER8R) enclave1/enclave1.edl
	@cd enclave1 && $(SGX_EDGER8R) --use-prefix --trusted ../enclave1/enclave1.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

enclave1/%.o: enclave1/%.c
	@$(CC) -nostdinc $(Enclave_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

enclave1.so: enclave1/enclave1_t.o $(Enclave_C_Objects_1) $(Trust_Agent_Lib_Name)
	@$(CC) enclave1/enclave1_t.o $(Enclave_C_Objects_1) $(Trust_Agent_Lib_Name) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Name_1): enclave1.so
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave1/enclave1_private.pem -enclave enclave1.so -out $@ -config enclave1/enclave1.config.xml
	@echo "SIGN =>  $@"

enclave2/enclave2_t.c: $(SGX_EDGER8R) enclave2/enclave2.edl
	@cd enclave2 && $(SGX_EDGER8R)  --use-prefix --trusted ../enclave2/enclave2.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave2/%.o: enclave2/%.c
	@$(CC) -nostdinc $(Enclave_Compile_Flags) -c $< -o $@
	@echo "CC  <=  $<"

enclave2.so: enclave2/enclave2_t.o $(Enclave_C_Objects_2) $(Trust_Agent_Lib_Name)
	@$(CC) enclave2/enclave2_t.o $(Enclave_C_Objects_2) $(Trust_Agent_Lib_Name) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Name_2): enclave2.so
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave2/enclave2_private.pem -enclave enclave2.so -out $@ -config enclave2/enclave2.config.xml
	@echo "SIGN =>  $@"

######## Clean ########
.PHONY: clean

clean:
	@rm -rf $(App_Name) $(AS_Name) *.so *.a app/*.o enclave0/*.o enclave0/*_t.* enclave0/*_u.* enclave1/*.o enclave1/*_t.* enclave1/*_u.* enclave2/*.o enclave2/*_t.* enclave2/*_u.* trusted_share_code/*.o trusted_agent_code/*.o lib/*.o as/*.o 
