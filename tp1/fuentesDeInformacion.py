from scapy.all import *
import math
from mediciones import *

path = 'packets/PacketsTomas-stream.pcap'

S1 = {}

def calcularProbabilidades(S):
    N = sum(S.values())
    S2 = S.copy()
    for key in S2:
        S2[key] = round(S2[key]/N,5)
        
    return S2

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

def informacionEvento(probabilidadEvento):
    return -math.log2(probabilidadEvento)

def informacionDeCadaSimbolo(fuente):
    S = {}
    for simbolo in fuente:
        S[simbolo] = informacionEvento(fuente[simbolo])
        
    return S

sniff(offline=path,prn=callback)
packets = rdpcap(path)
# mostrar_fuente(S1)
S1Probabilidades = calcularProbabilidades(S1)
S1Informacion = informacionDeCadaSimbolo(S1Probabilidades)
S1Entropia = entropia(S1)


print('Probabilidad de cada símbolo: ', S1Probabilidades)
print('Unicast vs Broadcast: ',unicastVsBroadCast(packets))
print('Porcentaje de cada Protocolo: ', porcentajeDeCadaProtocolo(packets))
print('Entropía de la red: ', S1Entropia)
informacionVsEntropia(S1Informacion,S1Entropia)

# graficoBarras(S1Probabilidades,S1Informacion)