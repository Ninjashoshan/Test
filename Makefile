export ARCHS = arm64
export TARGET = iphone:clang:latest:10.0

# If building against an older SDK on your own Theos, set e.g.:
# export SDKVERSION = 10.3

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GSALogger
GSALogger_FILES = Tweak.xm
GSALogger_FRAMEWORKS = Foundation
GSALogger_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

include $(THEOS)/makefiles/tweak.mk

after-install::
	install.exec "killall -9 akd || true"
