# Gökhan Has - 161044067
# CSE470 PROJE

import math
from aes import AESAlgorithm
from helper import *

class CBC():
    """
    CBC moduna göre AES şifrelemesi yapılacaktır. Bu mod için AESAlgorithm objesi
    üzerinden işlem yapılmaktadır.
    """
    aes = AESAlgorithm()

    def CBC_degiskenleri_olustur(self):
        return [0] * 16, [0] * 16, []

    def CBC_degiskenleri_olustur_2(self):
        return [], [], [], [0] * 16, []

    def matrix_degerleri_al(self, indeks):
        return 16*indeks, 16*indeks+16

    def matrixi_coz(self, bir, iki, uc, dort, cozumYonu):
        """
        Sifreleme veya sifreyi çözme algoritmalarına göre XOR işleminin
        nasıl yapılacağını belirleyen fonksiyondur. XOR işlemi yapılır ve değiştirilen
        değişken geri döndürülür.
        :param bir:
        :param iki:
        :param uc:
        :param dort:
        :param cozumYonu:
        :return:
        """
        for i in range(16):
            if cozumYonu == 0:
                bir[i] = iki[i] ^ uc[i]
            else:
                bir[i] = iki[i] ^ dort[i]
        return bir

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

    def kontrol(self, deger_1, deger_2):
        """
        Parametre olarak gönderilen değerlerinin hangisini büyük,
        küçük olduğunun anlaşılması için yazılan fonksiyondur.
        :param deger_1:
        :param deger_2:
        :return:
        """
        if deger_2 > deger_1:
            return deger_2
        return deger_1


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
        veri, sifreli_veri, sonuc = self.CBC_degiskenleri_olustur()
        for j in range(int(math.ceil(float(len(gelen_veri)) / 16))):
            ilk_indeks, son_indeks = self.matrix_degerleri_al(j)
            son_indeks = self.kontrol(son_indeks, len(gelen_veri))
            plaintext = string_olustur(gelen_veri, ilk_indeks, son_indeks, 'CBC')
            veri = self.matrixi_coz(veri, plaintext, ilk_sifreleme_anahtari, sifreli_veri, j)
            sifreli_veri = self.aes.sifreleme_ve_cozme(veri, anahtar, boyut, 'encrypt')
            sonuc = self.doldur(sonuc, sifreli_veri, 16)
        return sonuc

    def sifreyi_coz(self, gelen_veri, boyut, anahtar, boyut_2, ilk_sifreleme_anahtari):
        """
        AES objesinin şifreyi çözme fonksiyonun çağrıldığı fonksiyondur. Gönderilen veri
        üzerinde teker teker şifreler çözülür ve şifrelenmemiş olan sonuç string veri tipinde
        dödürülür.
        :param gelen_veri:
        :param boyut:
        :param anahtar:
        :param boyut_2:
        :param ilk_sifreleme_anahtari:
        :return:
        """
        sifreli_veri, veri, cikis_verisi, metin, sonuc = self.CBC_degiskenleri_olustur_2()
        for j in range(int(math.ceil(float(len(gelen_veri)) / 16))):
            ilk_indeks, son_indeks = self.matrix_degerleri_al(j)
            if j * 16 + 16 > len(gelen_veri):
                son_indeks = len(gelen_veri)
            sifreli_veri = gelen_veri[ilk_indeks:son_indeks]
            cikis_verisi = self.aes.sifreleme_ve_cozme(sifreli_veri, anahtar, boyut_2, 'decrypt')
            metin = self.matrixi_coz(metin, cikis_verisi, ilk_sifreleme_anahtari, veri, j)
            if boyut is not None and boyut < son_indeks:
                sonuc = self.doldur_2(sonuc, metin, boyut - ilk_indeks)
            else:
                sonuc = self.doldur_2(sonuc, metin, son_indeks - ilk_indeks)
            veri = sifreli_veri
        return "".join(sonuc)

