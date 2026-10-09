#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unordered_map>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

// Multiset Jaccard over collision-free byte trigrams. This is a heuristic,
// never evidence that an authorization policy has been violated.
extern "C" EXPORT double probekit_similarity(const unsigned char* a, std::size_t an,
                                             const unsigned char* b, std::size_t bn) noexcept {
    try {
        if ((!a && an) || (!b && bn)) return -1.0;
        if (an == bn && (!an || std::memcmp(a, b, an) == 0)) return 1.0;
        if (an < 3 || bn < 3) return 0.0;
        using Counts = std::unordered_map<std::uint32_t, std::size_t>;
        auto count = [](const unsigned char* data, std::size_t size) {
            Counts counts;
            for (std::size_t i = 0; i + 2 < size; ++i) {
                auto key = (std::uint32_t(data[i]) << 16) |
                           (std::uint32_t(data[i + 1]) << 8) | data[i + 2];
                ++counts[key];
            }
            return counts;
        };
        auto left = count(a, an);
        auto right = count(b, bn);
        std::size_t intersection = 0;
        for (const auto& item : left) {
            auto found = right.find(item.first);
            if (found != right.end()) intersection += std::min(item.second, found->second);
        }
        return double(intersection) / double(an - 2 + bn - 2 - intersection);
    } catch (...) {
        return -1.0;
    }
}
