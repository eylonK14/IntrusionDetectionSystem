#!/usr/bin/env python3

import os
import gi
import sys
import pprint
import scapy.all as scapy
from collections import defaultdict

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, Gdk, Graphene, GLib

global pktinfo


# Flow tracker
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.packets_sent = 0
        self.packets_received = 0
        self.size_of_sent_data = 0
        self.size_of_received_data = 0

    def __str__(self):
        return f"""
Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}
Protocol: {self.proto}
Packets Sent: {self.packets_sent}
Packets Received: {self.packets_received}
Sent Data (bytes): {self.size_of_sent_data}
Received Data (bytes): {self.size_of_received_data}
"""


# Dictionary to store flows
flows = defaultdict(Flow)


# Function to create flow key based on 5-tuple
def create_flow_key(packet):
    # Extract necessary information for the 5-tuple
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    # proto_num = packet[scapy.IP].proto
    # proto = proto_name_by_num(proto_num)
    proto = packet.payload.layers()[1].__name__
    src_port = 0
    dst_port = 0

    # For protocols like TCP and UDP, ports are important
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        src_port = packet.sport
        dst_port = packet.dport

    # Ensure the lower IP and port always come first in the flow key
    if (src_ip, src_port) > (dst_ip, dst_port):
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port

    return (src_ip, dst_ip, src_port, dst_port, proto)


# Packet handler function
def packet_handler(packet):
    if packet.haslayer(scapy.IP):
        # Create a unique flow key based on the 5-tuple
        flow_tuple = create_flow_key(packet)
        flow_key = f'{flow_tuple}'

        global flow_list

        # Check if this flow already exists
        if flow_key not in flows:
            flows[flow_key] = Flow(*flow_tuple)
            for item in list(flows.keys()):
                flow_list.append(item)
            pktinfo.set_label(f'{list(flows.keys())}'.replace('), ', ')\n'))

        # Determine whether the packet is sent or received
        if packet[scapy.IP].src == flows[flow_key].src_ip:
            flows[flow_key].packets_sent += 1
        else:
            flows[flow_key].packets_received += 1

        # Output flow information in real-time
        # os.system("clear")  # Clear the console for better readability
        # print(f"Updated Flow Information:\n{flows[flow_key]}")
        # print(f'{flows.keys()=}')
        # print(dict(flows))

        # Prints the nicely formatted dictionary
        # pprint.pprint(dict(flows))


class Custom(Gtk.Widget):
    def __init__(self):
        super().__init__()
        self.set_size_request(30, 30)

    def do_snapshot(self, s):
        # s.save()
        print("sn")
        red = Gdk.RGBA()
        # red.red = 1.
        # red.green = 0.
        # red.blue = 0.
        # red.alpha = 1.
        r = Graphene.Rect()
        r.init(0, 0, 70, 70)
        print(r)
        print(r.get_height())
        red.red = 1
        red.alpha = 1
        print(red.to_string())
        s.append_color(red, r)
        # s.restore()

    def do_measure(self, orientation, for_size):
        print("m")
        return 50, 50, -1, -1


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_default_size(600, 250)
        self.set_title("MyApp")

        # Main layout containers
        self.box1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.box2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.box3 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self.box2.set_spacing(10)
        self.box2.set_margin_top(10)
        self.box2.set_margin_bottom(10)
        self.box2.set_margin_start(10)
        self.box2.set_margin_end(10)

        self.set_child(self.box1)  # Horizontal box to window
        self.box1.append(self.box2)  # Put vert box in that box
        self.box1.append(self.box3)  # And another one, empty for now

        # Add a button
        self.button = Gtk.Button(label="Hello")
        self.button.connect('clicked', self.hello)
        # But button in the first of the two vertical boxes
        self.box2.append(self.button)

        # Add a check button
        self.check = Gtk.CheckButton(label="And goodbye?")
        self.box2.append(self.check)

        # Add a box containing a switch and label
        self.switch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.switch_box.set_spacing(5)
        self.switch = Gtk.Switch()
        self.switch.set_active(True)  # Let's default it to on
        # Lets trigger a function on state change
        self.switch.connect("state-set", self.switch_switched)
        self.label = Gtk.Label(label="A switch")
        self.switch_box.append(self.switch)
        self.switch_box.append(self.label)
        self.box2.append(self.switch_box)

        self.slider = Gtk.Scale()
        self.slider.set_digits(0)  # Number of decimal places to use
        self.slider.set_range(0, 10)
        self.slider.set_draw_value(True)  # Show a label with current value
        self.slider.set_value(5)  # Sets the current value/position
        self.slider.connect('value-changed', self.slider_changed)
        self.box2.append(self.slider)

        self.dropdown = Gtk.DropDown()
        self.dropdown.connect('notify::selected-item', self.on_string_selected)
        self.strings = Gtk.StringList()
        self.dropdown.props.model = self.strings
        self.strings.append('None')
        # Populate the list
        for item in scapy.get_if_list():
            self.strings.append(item)

        self.box2.append(self.dropdown)

        self.sniff = Gtk.Button(label="Start Sniffing on selected interface")
        self.sniff.connect('clicked', self.start_sniff)
        self.box2.append(self.sniff)

        global pktinfo, flow_list
        pktinfo = Gtk.Label(label="lorem ipsum")
        self.box3.append(pktinfo)

        self.flow_selector = Gtk.DropDown()
        self.flow_info = Gtk.Label(label="lorem ipsum")
        self.flow_selector.connect('notify::selected-item', self.on_flow_selected)
        flow_list = Gtk.StringList()
        self.flow_selector.props.model = flow_list
        flow_list.append('None')
        self.box2.append(self.flow_selector)

        self.box3.append(self.flow_info)

        # self.items = scapy.get_if_list()
        # self.strings.append('None')
        # # Populate the list
        # for item in self.items:
        #     self.strings.append(item)


        self.header = Gtk.HeaderBar()
        self.set_titlebar(self.header)

        # Create a new "Action"
        action = Gio.SimpleAction.new("something", None)
        action.connect("activate", self.print_something)
        # Here the action is being added to the window,
        # but you could add it to the application or an "ActionGroup"
        self.add_action(action)

        # Create a new menu, containing that action
        menu = Gio.Menu.new()
        # Or you would do app.grape if you had attached
        # the action to the application
        menu.append("Do Something", "win.something")
        # Create a popover
        self.popover = Gtk.PopoverMenu()  # Create a new popover menu
        self.popover.set_menu_model(menu)
        # Create a menu button
        self.hamburger = Gtk.MenuButton()
        self.hamburger.set_popover(self.popover)
        # Give it a nice icon
        self.hamburger.set_icon_name("open-menu-symbolic")
        # Add menu button to the header bar
        self.header.pack_start(self.hamburger)

        # set app name
        GLib.set_application_name("My App")

        # Add an `about` dialog
        action = Gio.SimpleAction.new("about", None)
        action.connect("activate", self.show_about)
        # Here the action is being added to the window,
        # but you could add it to the
        self.add_action(action)
        menu.append("About", "win.about")

        # evc = Gtk.GestureClick.new()
        # evc.connect("pressed", self.click)  # could be "released"
        # self.add_controller(evc)
        # self.dw.add_controller(evk)

        evk = Gtk.EventControllerKey.new()
        evk.connect("key-pressed", self.key_press)
        self.add_controller(evk)

        # custom = Custom()
        # custom.set_hexpand(True)
        # custom.set_vexpand(True)
        # self.box3.append(custom)

    def show_about(self, action, param):
        self.about = Gtk.AboutDialog()
        self.about.set_transient_for(self)
        # self.about.set_modal(self)

        self.about.set_authors(["Your Name"])
        self.about.set_copyright("Copyright 2022 Your Full Name")
        self.about.set_license_type(Gtk.License.GPL_3_0)
        self.about.set_website("https://example.com")
        self.about.set_website_label("My Website")
        self.about.set_version("1.0")
        self.about.set_logo_icon_name("org.example.example")

        self.about.show()

    def start_sniff(self, button):
        print(f'{self.interface=}')
        if self.interface != "None":
            print(f"Sniffing on interface: {self.interface}")
            self.sniffer = scapy.AsyncSniffer(prn=packet_handler, iface=self.interface)
            self.sniffer.start()
            # scapy.sniff(iface=self.interface, prn=packet_handler, store=False)

    def on_string_selected(self, dropdown, _pspec):
        # Selected Gtk.StringObject
        selected = self.dropdown.props.selected_item
        if selected is not None:
            self.interface = selected.props.string
            print('Selected', self.interface)

    def on_flow_selected(self, dropdown, _pspec):
        selected = self.flow_selector.props.selected_item
        if selected is not None:
            flow = selected.props.string
            print(f'{flow=}') 
            print(f'{type(flows)=}')
            # self.flow_info.set_label(f'{flows[flow]}')

    def key_press(self, event, keyval, keycode, state):
        if keyval == Gdk.KEY_q and state & Gdk.ModifierType.CONTROL_MASK:
            result = self.sniffer.stop()
            print(result)
            self.close()

    def show_open_dialog(self, button):
        print("dialog opened")
        self.open_dialog.show()

    def open_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            filename = file.get_path()
            print(filename)

    def click(self, gesture, data, x, y):
        print(f'{gesture=}, {data=}, {x=}, {y=}')
        # self.dw.queue_draw()  # Force a redraw

    def print_something(self, action, param):
        print("Something!")

    def slider_changed(self, slider):
        print(int(slider.get_value()))

    def switch_switched(self, switch, state):
        print(f"The switch has been switched {'on' if state else 'off'}")

    def hello(self, button):
        print("Hello world")
        if self.check.get_active():
            print("Goodbye world!")
            self.close()


class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        self.win = MainWindow(application=app)
        self.win.present()


app = MyApp(application_id="com.example.GtkApplication")
app.run(sys.argv)
