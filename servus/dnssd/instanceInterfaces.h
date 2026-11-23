/* This file is part of Servus <https://github.com/HBPVIS/Servus>
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License version 3.0 as published
 * by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef SERVUS_DNSSD_INSTANCEINTERFACES_H
#define SERVUS_DNSSD_INSTANCEINTERFACES_H

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace servus
{
namespace dnssd
{
/**
 * The interfaces each browsed instance is currently seen on.
 *
 * DNS-SD browsing on all interfaces reports an add and a remove per interface,
 * so an instance is only gone once the last of its interfaces has reported it
 * removed. Acting on the first remove loses an instance that's still there:
 * if it re-registers under the same name (a restarted service) before all the
 * old interfaces have reported, the browser drops the new one, and no further
 * add arrives for an interface on which the name never went away.
 */
class InstanceInterfaces
{
public:
    /** Records the instance on an interface. @return true if it's the first. */
    bool add(const std::string& instance, const uint32_t interfaceIdx)
    {
        auto& interfaces = _interfaces[instance];
        const bool first = interfaces.empty();
        interfaces.insert(interfaceIdx);
        return first;
    }

    /**
     * Records the instance gone from an interface.
     * @return true if it's now on no interface: the instance is gone.
     */
    bool remove(const std::string& instance, const uint32_t interfaceIdx)
    {
        const auto it = _interfaces.find(instance);
        if (it == _interfaces.end())
            return true; // never seen: nothing holds it

        it->second.erase(interfaceIdx);
        if (!it->second.empty())
            return false;

        _interfaces.erase(it);
        return true;
    }

    bool contains(const std::string& instance) const
    {
        return _interfaces.count(instance) != 0;
    }

    void clear() { _interfaces.clear(); }

private:
    std::map<std::string, std::set<uint32_t>> _interfaces;
};
}
}

#endif
