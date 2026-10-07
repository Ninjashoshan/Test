# iPhone 5s = arm64. Rootful jailbreak (iOS 10.3.3), Cydia Substrate.
export TARGET = iphone:clang:latest:10.0
export ARCHS = arm64
INSTALL_TARGET_PROCESSES = Twitter

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TwLog
TwLog_FILES = Tweak.x
TwLog_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
TwLog_FRAMEWORKS = UIKit WebKit

include $(THEOS_MAKE_PATH)/tweak.mk
