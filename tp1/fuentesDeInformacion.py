from scapy.all import *
import math

path = './PacketsTomas.pcap'

S1 = {}

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ "%s : %.5f" % (d,k/N) for d,k in simbolos ]))
    print()

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0

def entropia(fuente):
    suma = 0.0
    N = sum(fuente.values())
    for s_i in fuente.values():
        probabilidad = s_i/N
        suma += probabilidad * informacionEvento(probabilidad)

    return suma

def informacionEvento(evento):
    return -math.log2(evento)

sniff(offline=path,prn=callback)
packets = rdpcap(path)
mostrar_fuente(S1)
print('Entropia: ',entropia(S1))