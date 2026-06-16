REGISTRY     ?= example.com/adi
VERSION      ?= latest
POST_DB_PATH ?= post.db
IMAGE_NAME   ?= grondig
OUTPUT_DIR   ?= _output

IMAGE_REF  := $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
XPKG_FILE  := $(OUTPUT_DIR)/$(IMAGE_NAME).xpkg
REPO_ROOT  := $(CURDIR)/../..

.PHONY: all image xpkg push clean

all: image xpkg

image:
	podman build --build-arg POST_DB_PATH=$(POST_DB_PATH) \
		-t $(IMAGE_REF) -f $(CURDIR)/Containerfile $(REPO_ROOT)

xpkg: image
	crossplane xpkg build \
		--package-root=$(CURDIR)/package \
		--embed-runtime-image=$(IMAGE_REF) \
		--package-file=$(XPKG_FILE)

push: $(XPKG_FILE)
	crossplane xpkg push --package-files=$(XPKG_FILE) $(IMAGE_REF)

clean:
	rm -rf $(OUTPUT_DIR)
	podman rmi $(IMAGE_REF) 2>/dev/null || true
