/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/ice/candidatepair.hpp"

namespace stice::ice {

// All logic is in the header for now (computePriority is a pure function;
// CandidatePair is a POD-like struct). This .cpp exists so the CMakeLists
// reference resolves and to host any future non-inline helpers.

} // namespace stice::ice
