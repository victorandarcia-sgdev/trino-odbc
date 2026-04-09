#pragma once

#include "../../../util/windowsLean.hpp"
#include <string>

HWND buttonMaker(HWND form,
                 int horizOffset,
                 int buttonId,
                 std::string buttonText,
                 int vertOffset = 300);