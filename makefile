NAME = pestilence

SRC_DIR = src/
OBJ_DIR = obj/
COMP = nasm
ASMFLAGS = -f elf64 -F dwarf
LD = ld
CONTAINER_NAME = docker_pestilence

SRC_FILES = pestilence.asm
SRC = $(addprefix $(SRC_DIR), $(SRC_FILES))

OBJ_FILES = $(SRC_FILES:.asm=.o)
OBJ = $(addprefix $(OBJ_DIR), $(OBJ_FILES))

all: obj $(NAME)

obj:
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)%.o: $(SRC_DIR)%.asm
	$(COMP) $(ASMFLAGS) -o $@ $< 

$(NAME): $(OBJ)
	$(LD) $(LD_FLAGS) $(OBJ) -o $(NAME)
# 	@tmp_dir=$$(mktemp -d); \
#     ./preprocess_asm.sh > $${tmp_dir}/_asm_encrypt_addresses; \
#     gcc src/pre_encrypter.c -o encryptor; \
#     ./encryptor $${tmp_dir}/_asm_encrypt_addresses; \
#     rm encryptor; rm -rf $${tmp_dir}

fclean: clean
	@rm -f $(NAME)
	@rm -Rf $(OBJ_DIR)
	@rm -f crypt

clean:
	@rm -Rf $(OBJ_DIR)

build: 
	@echo "Building image $(CONTAINER_NAME)"
	docker build -t $(CONTAINER_NAME) .

docker: 
	@echo "Run container $(CONTAINER_NAME)"
	docker run --rm -it --net=bridge \
  	--cap-add=NET_ADMIN \
  	-v $(CURDIR):/app \
  	$(CONTAINER_NAME)

test: all
	./test.sh
	
re: fclean all
