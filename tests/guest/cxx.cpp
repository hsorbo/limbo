/*
 * Copyright © 2026 Ole André Vadla Ravnås
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <algorithm>
#include <filesystem>
#include <format>
#include <future>
#include <map>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "check.h"

static int parse(const std::string &text);

int
main()
{
	std::vector<std::future<int>> futures;
	for (int i = 0; i < 8; i++) {
		futures.push_back(std::async(
				std::launch::async, [i] { return i * i; }));
	}
	int sum = 0;
	for (auto &future : futures) {
		sum += future.get();
	}
	CHECK(sum == 140);

	CHECK(std::format("{}-{:04}", "limbo", 42) == "limbo-0042");

	std::regex pattern("([a-z]+)=(\\d+)");
	std::smatch match;
	std::string input = "answer=42";
	CHECK(std::regex_match(input, match, pattern));
	CHECK(match[1] == "answer" && match[2] == "42");

	bool caught = false;
	try {
		parse("not a number");
	} catch (const std::invalid_argument &) {
		caught = true;
	}
	CHECK(caught);

	std::map<std::string, int> counts;
	for (const auto &entry :
			std::filesystem::directory_iterator("/usr/lib")) {
		counts[entry.path().extension().string()]++;
	}
	CHECK(counts[".dylib"] > 0);

	std::jthread worker([&counts] { counts["thread"] = 1; });
	worker.join();
	CHECK(counts["thread"] == 1);
	return 0;
}

static int
parse(const std::string &text)
{
	return std::stoi(text);
}
