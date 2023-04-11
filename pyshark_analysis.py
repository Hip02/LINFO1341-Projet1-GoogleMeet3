import pyshark
import datetime
import ipaddress


def get_interval(arrival_time, intervals, samples):
    for i, interval in enumerate(intervals):
        a, b = interval
        if a <= arrival_time < b:
            sample_size = (b - a) / samples
            index = int((arrival_time-a) // sample_size)
            #print(f"a : {a}, b : {b}, t : {arrival_time}, sample size : {sample_size}, index : {index}")
            return i, index
    return None, None


def count_packets_size(file_name, intervals, labels, samples, local_ip):
    """
    @:param file_name : "test.pcapng" (str)
    @:param intervals : [(0, 5), (10, 20)] (list of tuples)
    @:param labels : {(0, 5) : 'camera', (10, 20) : 'micro'} (dict)
    @:param samples : 5 (int)
    @:param local_ip : "192.168.2.15" (str)

    @:return packets_length : {'camera' : [[..in..], [..out..]], 'micro' : [[..in..], [..out..]]} (dict)
    """
    packets_length = {val: [[], []] for val in labels.values()}

    capture = pyshark.FileCapture(file_name)

    time0 = datetime.datetime.fromtimestamp(float(capture[0].sniff_timestamp))

    for packet in capture:
        arrival_time = (datetime.datetime.fromtimestamp(float(packet.sniff_timestamp)) - time0).total_seconds()
        if 'ip' in packet:

            interval, index = get_interval(arrival_time, intervals, samples)
            if interval is None:
                continue

            label = labels[intervals[interval]]
            lengths = packets_length[label]

            if packet.ip.dst == local_ip:
                current_in = lengths[0]
                if index >= len(current_in):
                    current_in.append(int(packet.length))
                else:
                    current_in[index] += int(packet.length)

                lengths[0] = current_in

            elif packet.ip.src == local_ip:
                current_out = lengths[1]
                if index >= len(current_out):
                    current_out.append(int(packet.length))
                else:
                    current_out[index] += int(packet.length)

                lengths[1] = current_out

            packets_length[label] = lengths

    capture.close()

    return packets_length


intervals = [(150, 165), (175, 190), (200, 215), (230, 245)]
labels = {(150, 165): 'camera, micro', (175, 190): 'micro', (200, 215): 'camera', (230, 245): "rien"}
samples = 60
local_ip = "192.168.2.15"

packets_length = count_packets_size("call_avec_maman.pcapng", intervals, labels, samples, local_ip)

print(packets_length)
