# Gökhan Has - 161044067
# CSE470 PROJE

import math
from aes import AESAlgorithm
from helper import *

class OFB():
    """
    OFB moduna göre AES şifrelemesi yapılacaktır. Bu mod için AESAlgorithm objesi
    üzerinden işlem yapılmaktadır.
    """
    aes = AESAlgorithm()

    def OFB_degiskenleri_olustur(self):
        return [], [0] * 16, [], [0] * 16, []

    def OFB_degiskenleri_olustur_2(self):
        return [], [], [], [0] * 16, []

    def matrix_degerleri_al(self, indeks):
        return 16*indeks, 16*indeks+16

    def matrixi_coz(self, bir, iki, uc):
        """
        Sifreleme veya sifreyi çözme algoritmalarına göre XOR işleminin
        nasıl yapılacağını belirleyen fonksiyondur. XOR işlemi yapılır ve değiştirilen
        değişken geri döndürülür.
        :param bir:
        :param iki:
        :param uc:
        :return:
        """
        for i in range(16):
            if len(bir) - 1 < i:
                iki[i] = 0 ^ uc[i]
            elif len(uc) - 1 < i:
                iki[i] = bir[i] ^ 0
            elif len(bir) - 1 < i and len(uc) < i:
                iki[i] = 0 ^ 0
            else:
                iki[i] = bir[i] ^ uc[i]
        return iki


    def matrixi_coz_2(self, bir, iki, uc):
        """
        Sifreleme veya sifreyi çözme algoritmalarına göre XOR işleminin
        nasıl yapılacağını belirleyen fonksiyondur. XOR işlemi yapılır ve değiştirilen
        değişken geri döndürülür.
        :param bir:
        :param iki:
        :param uc:
        :return:
        """
        for i in range(16):
            if len(bir) - 1 < i:
                iki[i] = 0 ^ uc[i]
            elif len(uc) - 1 < i:
                iki[i] = bir[i] ^ 0
            elif len(bir) - 1 < i and len(uc) < i:
                iki[i] = 0 ^ 0
            else:
                iki[i] = bir[i] ^ uc[i]
        return iki

    def sifrele(self, gelen_veri, anahtar, boyut, ilk_sifreleme_anahtari):
        """
        AES objesinin şifreleme fonksiyonun çağrıldığı fonksiyondur. Gönderilen veri
        üzerinde teker teker şifreleme işlemi yapılır.
        :param gelen_veri:
        :param anahtar:
        :param boyut:
        :param ilk_sifreleme_anahtari:
        :return:
        """
        metin, veri, cikis_verisi, sifreli_veri, sonuc = self.OFB_degiskenleri_olustur();
        for j in range(int(math.ceil(float(len(gelen_veri)) / 16))):
            ilk_indeks, son_indeks = self.matrix_degerleri_al(j)
            son_indeks = self.kontrol(son_indeks, len(gelen_veri))
            metin = string_olustur(gelen_veri, ilk_indeks, son_indeks, 'OFB')
            if j==0:
                cikis_verisi = self.aes.sifreleme_ve_cozme(ilk_sifreleme_anahtari, anahtar, boyut, 'encrypt')
            else:
                cikis_verisi = self.aes.sifreleme_ve_cozme(veri, anahtar, boyut, 'encrypt')
            sifreli_veri = self.matrixi_coz(metin , sifreli_veri, cikis_verisi)
            sonuc = self.doldur(sonuc, sifreli_veri, son_indeks - ilk_indeks)
            veri = cikis_verisi
        return sonuc

    def sifreyi_coz(self, gelen_veri, anahtar, boyut, ilk_sifreleme_anahtari):
        """
        AES objesinin şifreyi çözme fonksiyonun çağrıldığı fonksiyondur. Gönderilen veri
        üzerinde teker teker şifreler çözülür ve şifrelenmemiş olan sonuç string veri tipinde
        dödürülür
        :param gelen_veri:
        :param anahtar:
        :param boyut:
        :param ilk_sifreleme_anahtari:
        :return:
        """
        sifreli_metin, veri, cikis_veri, metin, sonuc = self.OFB_degiskenleri_olustur_2()
        for j in range(int(math.ceil(float(len(gelen_veri)) / 16))):
            ilk_indeks, son_indeks = self.matrix_degerleri_al(j)
            if j * 16 + 16 > len(gelen_veri):
                son_indeks = len(gelen_veri)
            sifreli_metin = gelen_veri[ilk_indeks:son_indeks]
            if j==0:
                cikis_veri = self.aes.sifreleme_ve_cozme(ilk_sifreleme_anahtari, anahtar, boyut, 'encrypt')
            else:
                cikis_veri = self.aes.sifreleme_ve_cozme(veri, anahtar, boyut, 'encrypt')
            metin = self.matrixi_coz_2(cikis_veri, metin, sifreli_metin)
            sonuc = self.doldur_2(sonuc, metin, son_indeks - ilk_indeks)
            veri = cikis_veri
        return "".join(sonuc)

    def kontrol(self, deger_1, deger_2):
        """
        Parametre olarak gönderilen değerlerinin hangisini büyük,
        küçük olduğunun anlaşılması için yazılan fonksiyondur.
        :param deger_1:
        :param deger_2:
        :return:
        """
        if deger_2 > deger_1:
            return deger_1
        return deger_2

    def doldur(self, dizin, dizin_2, boyut):
        """
        İlk parametredeki listeye ikin parametredeki listenin elemanlarını ekler.
        Yani iki listeyi birleştiren fonksiyondur.
        :param dizin:
        :param dizin_2:
        :param boyut:
        :return:
        """
        for i in range(boyut):
            dizin.append(dizin_2[i])
        return dizin

    def doldur_2(self, dizin, dizin_2, boyut):
        """
        İlk parametredeki listeye ikin parametredeki listenin elemanlarını ekler.
        Yani iki listeyi birleştiren fonksiyondur. İkinci listenin elemanları character
        veri tipine çevrilir.
        :param dizin:
        :param dizin_2:
        :param boyut:
        :return:
        """
        for i in range(boyut):
            dizin.append(chr(dizin_2[i]))
        return dizin