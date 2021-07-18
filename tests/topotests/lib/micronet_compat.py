# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
import logging
import os
import subprocess
import traceback

from .micronet import LinuxNamespace, Micronet

logger = logging.getLogger(__name__)


def set_log_level(level):
    logger.setLevel(level)


setLogLevel = set_log_level  # mininet compat


class Node(LinuxNamespace):
    """Node (mininet compat)."""

    def __init__(self, name, **kwargs):
        """
        Create a Node.
        """
        self.params = kwargs

        if "private_mounts" in kwargs:
            private_mounts = kwargs["private_mounts"]
        else:
            private_mounts = kwargs.get("privateDirs", [])

        super(Node, self).__init__(name, private_mounts=private_mounts)

    def cmd(self, cmd, **kwargs):
        """Execute a command."""

        defaults = {"stderr": subprocess.STDOUT}
        defaults.update(kwargs)

        rc, stdout, _ = self.cmd_status(cmd, **defaults)
        if rc:
            cmd_str = self._get_cmd_str(cmd)
            logging.warning(
                '%s: cmd("%s"): Failed stack:\n%s',
                self,
                cmd_str,
                "".join(traceback.format_stack(limit=12)),
            )

        return stdout

    def config(self, lo="up", **params):
        """Called by Micronet when topology is built (but not started)."""
        # mininet brings up loopback here.
        del params
        del lo

    def intfNames(self):
        return self.intfs

    # Run a command in a new window (gnome-terminal, screen, tmux, xterm)
    def runInWindow(self, cmd, title=None):
        logging.warning("runInWindow(%s)", cmd)
        if "TMUX" not in os.environ and "STY" not in os.environ:
            return

        del title

        nscmd = self.pre_cmd_str + cmd
        if "TMUX" in os.environ:
            tmux_pane_arg = os.getenv("TMUX_PANE", "")
            tmux_pane_arg = " -t " + tmux_pane_arg if tmux_pane_arg else ""
            wcmd = "tmux split-window -h"
            if tmux_pane_arg:
                wcmd += tmux_pane_arg
            cmd = "{} {}".format(wcmd, nscmd)
        elif "STY" in os.environ:
            if os.path.exists(
                "/run/screen/S-{}/{}".format(os.environ["USER"], os.environ["STY"])
            ):
                wcmd = "screen"
            else:
                wcmd = "sudo -u {} screen".format(os.environ["SUDO_USER"])
            cmd = "{} {}".format(wcmd, nscmd)
        self.cmd(cmd)

        # Re-adjust the layout
        if "TMUX" in os.environ:
            self.cmd("tmux select-layout main-horizontal")


class Topo(object):  # pylint: disable=R0205
    """
    Topology object passed to Micronet to build actual topology.
    """

    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.name = kwargs["name"] if "name" in kwargs else "unnamed"
        self.tgen = kwargs["tgen"] if "tgen" in kwargs else None

        logging.debug("%s: Creating", self)

        self.nodes = {}
        self.hosts = {}
        self.switches = {}
        self.links = {}

        # if "no_init_build" in kwargs and kwargs["no_init_build"]:
        #     return

        # This needs to move outside of here. Current tests count on it being called on init;
        # however, b/c of this there is lots of twisty logic to support topogen based tests where
        # the build routine must get get_topogen() so topogen can then set it's topogen.topo to the
        # class it's in the process of instantiating (this one) b/c build will use topogen before
        # the instantiation completes.
        self.build(*args, **kwargs)

    def __str__(self):
        return "Topo({})".format(self.name)

    def build(self, *args, **kwargs):
        "Overriden by real class"
        del args
        del kwargs
        raise NotImplementedError("Needs to be overriden")

    def addHost(self, name, **kwargs):
        logging.debug("%s: addHost %s", self, name)
        self.nodes[name] = dict(**kwargs)
        self.hosts[name] = self.nodes[name]
        return name

    addNode = addHost

    def addSwitch(self, name, **kwargs):
        logging.debug("%s: addSwitch %s", self, name)
        self.nodes[name] = dict(**kwargs)
        if "cls" in self.nodes[name]:
            logging.warning("Overriding Bridge class with micronet.Bridge")
            del self.nodes[name]["cls"]
        self.switches[name] = self.nodes[name]
        return name

    def addLink(self, name1, name2, **kwargs):
        """Link up switch and a router.

        possible kwargs:
        - intfName1 :: switch-side interface name - sometimes missing
        - intfName2 :: router-side interface name
        - addr1 :: switch-side MAC used by test_ldp_topo1 only
        - addr2 :: router-side MAC used by test_ldp_topo1 only
        """
        if1 = (
            kwargs["intfName1"]
            if "intfName1" in kwargs
            else "{}-{}".format(name1, name2)
        )
        if2 = (
            kwargs["intfName2"]
            if "intfName2" in kwargs
            else "{}-{}".format(name2, name1)
        )

        logging.debug("%s: addLink %s %s if1: %s if2: %s", self, name1, name2, if1, if2)

        if name1 in self.switches:
            assert name2 in self.hosts
            swname, rname = name1, name2
        elif name2 in self.switches:
            assert name1 in self.hosts
            swname, rname = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            swname, rname = name1, name2

        if swname not in self.links:
            self.links[swname] = {}

        if rname not in self.links[swname]:
            self.links[swname][rname] = set()

        self.links[swname][rname].add((if1, if2))


class Mininet(Micronet):
    """
    Mininet using Micronet.
    """

    g_mnet_inst = None

    def __init__(self, controller=None, topo=None):
        """
        Create a Micronet.
        """
        assert not controller

        if Mininet.g_mnet_inst is not None:
            Mininet.g_mnet_inst.stop()
        Mininet.g_mnet_inst = self

        self.configured_hosts = set()
        self.host_params = {}
        self.prefix_len = 8

        logging.debug("%s: Creating", self)

        # SNMPd used to require this, which was set int he mininet shell
        # that all commands executed from. This is goofy default so let's not
        # do it if we don't have to. The snmpd.conf files have been updated
        # to set permissions to root:frr 770 to make this unneeded in that case
        # os.umask(0)

        super(Mininet, self).__init__()

        if topo and topo.hosts:
            logging.debug("Adding hosts: %s", topo.hosts.keys())
            for name in topo.hosts:
                self.add_host(name, **topo.hosts[name])

        if topo and topo.switches:
            logging.debug("Adding switches: %s", topo.switches.keys())
            for name in topo.switches:
                self.add_switch(name, **topo.switches[name])

        if topo and topo.links:
            logging.debug("Adding links: ")
            for swname in sorted(topo.links):
                for rname in sorted(topo.links[swname]):
                    for link in topo.links[swname][rname]:
                        self.add_link(swname, rname, link[0], link[1])

        if topo:
            # Now that topology is built, configure hosts
            self.configure_hosts()

    def __str__(self):
        return "Mininet()"

    def configure_hosts(self):
        """
        Configure hosts once the topology has been built.

        This function can be called multiple times if routers are added to the topology
        later.
        """
        if not self.hosts:
            return

        logging.debug("Configuring hosts: %s", self.hosts.keys())

        for name in sorted(self.hosts.keys()):
            if name in self.configured_hosts:
                continue

            host = self.hosts[name]
            first_intf = host.intfs[0] if host.intfs else None
            params = self.host_params[name]

            if first_intf and "ip" in params:
                ip = params["ip"]
                i = ip.find("/")
                if i == -1:
                    plen = self.prefix_len
                else:
                    plen = int(ip[i + 1 :])
                    ip = ip[:i]

                host.cmd("ip addr add {}/{} dev {}".format(ip, plen, first_intf))

            if "defaultRoute" in params:
                host.cmd("ip route add default {}".format(params["defaultRoute"]))

            host.config()

            self.configured_hosts.add(name)

    def cli(self):
        raise NotImplementedError("writeme")

    def add_host(self, name, cls=Node, **kwargs):
        """Add a host to micronet."""

        self.host_params[name] = kwargs
        super(Mininet, self).add_host(name, cls=cls, **kwargs)

    def start(self):
        """Start the micronet topology."""
        logging.debug("%s: Starting (no-op).", self)

    def stop(self):
        """Stop the mininet topology (deletes)."""
        logging.debug("%s: Stopping (deleting).", self)

        self.delete()

        logging.debug("%s: Stopped (deleted).", self)

        if Mininet.g_mnet_inst == self:
            Mininet.g_mnet_inst = None