# Gökhan Has - 161044067
# CSE470 PROJE

import os
import time
from helper import *
from CBC_Aes import CBC
from OFB_Aes import OFB


def sifrele_CBC(anahtar, metin):
    """
    CBC moduna göre AES şifrelemesi yapılır. Anahtar ve ilk
    anahtar rastgele oluşturulur. Part A,B için kullanılmıştır.
    İlgili modun objesi oluşturularak işlemler yapılır.
    :param anahtar:
    :param metin:
    :return:
    """
    anahtar_listesi = list(map(ord, anahtar))
    metin = kontrol_desteksiz_karakter(metin)
    ilk_giris_anahtari = [i for i in os.urandom(16)]
    mod = CBC()
    return ''.join(map(chr, ilk_giris_anahtari)) + ''.join(map(chr, mod.sifrele(metin, anahtar_listesi, 16, ilk_giris_anahtari)))


def sifrele_OFB(anahtar, metin):
    """
    OFB moduna göre AES şifrelemesi yapılır. Anahtar ve ilk
    anahtar rastgele oluşturulur. Part A,B için kullanılmıştır.
    İlgili modun objesi oluşturularak işlemler yapılır.
    :param anahtar:
    :param metin:
    :return:
    """
    anahtar_listesi = list(map(ord, anahtar))
    ilk_giris_anahtari = [i for i in os.urandom(16)]
    mod = OFB()
    return ''.join(map(chr, ilk_giris_anahtari)) + ''.join(map(chr, mod.sifrele(metin,  anahtar_listesi, 16, ilk_giris_anahtari)))


def sifre_coz_CBC(anahtar, metin):
    """
    CBC moduna göre AES şifre çözmesi yapılır. Anahtar ve ilk
    anahtar sifreleme fonksiyonundaki değerlerden alınır.
    Part A,B için kullanılmıştır. İlgili modun objesi oluşturularak işlemler yapılır.
    :param anahtar:
    :param metin:
    :return:
    """
    anahtar_listesi = list(map(ord, anahtar))
    ilk_giris_anahtari = list(map(ord, metin[:16]))
    metin = list(map(ord, metin[16:]))
    mod = CBC()
    return mod.sifreyi_coz(metin, None, anahtar_listesi, 16, ilk_giris_anahtari)


def sifre_coz_OFB(anahtar, metin):
    """
    OFB moduna göre AES şifre çözmesi yapılır. Anahtar ve ilk
    anahtar sifreleme fonksiyonundaki değerlerden alınır.
    Part A,B için kullanılmıştır. İlgili modun objesi oluşturularak işlemler yapılır.
    :param anahtar:
    :param metin:
    :return:
    """
    anahtar_listesi = list(map(ord, anahtar))
    ilk_giris_anahtari = list(map(ord, metin[:16]))
    data = list(map(ord, metin[16:]))
    mod = OFB()
    return mod.sifreyi_coz(data, anahtar_listesi, 16, ilk_giris_anahtari)


def ozut_hash(girdi):
    """
    Part C ve D de kullanmak için yazılmıştır. Girdinin özütü alınarak aes şifrelemesi
    yapılır. AES ile şifrelenen özüt dosyaya yazılmak üzere geri döner.
    :param girdi:
    :return:
    """
    anahtar = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]
    ilk_giris_anahtari = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    hash = OFB()

    yedek_text = []
    for i in girdi:
        yedek_text.append(int.from_bytes(i, 'big'))
    if len(yedek_text) < 256:
        while True:
            yedek_text.append(0x05)
            if len(yedek_text) == 256:
                break
    yedek_text = yedek_text[0:256]
    arr = []
    i = 0
    while i < len(yedek_text) - 1:
        arr.append(yedek_text[i] ^ yedek_text[i + 1])
        i += 2

    arr_2 = []
    i = 0
    while i < len(arr) - 1:
        arr_2.append(arr[i] ^ arr[i + 1])
        i += 2

    arr_3 = []
    i = 0
    while i < len(arr_2) - 1:
        arr_3.append(arr_2[i] ^ arr_2[i + 1])
        i += 2

    arr_4 = []
    i = 0
    while i < len(arr_3) - 1:
        arr_4.append(arr_3[i] ^ arr_3[i + 1])
        i += 2

    hash = hash.sifrele(girdi, anahtar, 16, ilk_giris_anahtari)
    return hash[-16:]


def anahtari_karaktere_çevirme(anahtar):
    """
    Oluşturulan integer tipindeki anahtar listesi chr metodu kullanılarak
    character veri tipine dönüştürülür.
    :param anahtar:
    :return:
    """
    yedek = []
    for i in anahtar:
        yedek.append(chr(i))
    return yedek


def test_fonksiyonu(mesaj):
    """
    Part A ve B için yazılan test fonksiyonudur. Parametre olarak gönderilen mesaj değişkeni
    hem CBC hem de OFB moduna göre şifrelenip, geri çözülür ve yaşanan adımlar teker teker
    kullanıcıya gösterilir.
    :param mesaj:
    :return:
    """
    yedek_mesaj = mesaj
    print("Şifrelenecek metin : ", mesaj)
    rastgele_anahtar = os.urandom(16)
    print("Rastgele anahtar oluşturuldu : ", rastgele_anahtar)
    rastgele_anahtar = anahtari_karaktere_çevirme(rastgele_anahtar)

    print("CBC moduna göre şifreleme yapılıyor ...")
    sifre = sifrele_CBC(rastgele_anahtar, mesaj)
    print("Şifreli hali : ", sifre)
    print("CBC moduna göre şifre çözülüyor ...")
    cozulen_mesaj = sifre_coz_CBC(rastgele_anahtar, sifre)
    print("Şifre çözüldü : ", cozulen_mesaj)
    print()
    print("OFB moduna göre şifreleme yapılıyor ...")
    sifre = sifrele_OFB(rastgele_anahtar, yedek_mesaj)
    print("Şifreli hali : ", sifre)
    print("OFB moduna göre şifre çözülüyor ...")
    cozulen_mesaj = sifre_coz_OFB(rastgele_anahtar, sifre)
    print("Şifre çözüldü : ", cozulen_mesaj)
    print("\n")

def secim_1():
    """
    Part A ve B için önceden yazılan test verileridir. Üç adet mesaj oluşturulmuştur.
    Her mesaj daha sonra test_fonksiyonu()'na gönderilir. Kullanıcıya basılan bilgi mesajlarının
    karışmaması için 1 saniye program her fonksiyon arası uyutulmuştur.
    :return:
    """
    print("Test verileri ile rastgele anahtar olusturularak her iki modda (CBC ve OFB) şifreleme ve çözme işlemleri yapılacaktır...")
    print("ÖNEMLİ NOT ! Çıktıların düzgün gözükmesi için her mesaj çözüldükten sonra 1 saniye bekletilmiştir !!!\n")

    mesaj_1 = "Bu mac sabaha kadar oynansa sonuc degismez."
    mesaj_2 = "Yarin acik havada yuruyus yapalim mi?"
    mesaj_3 = "Pandemi ne zaman bitecek? Yeter artik !"

    test_fonksiyonu(mesaj_1)
    time.sleep(1)
    test_fonksiyonu(mesaj_2)
    time.sleep(1)
    test_fonksiyonu(mesaj_3)
    time.sleep(1)

def secim_2():
    """
    Part C için yapılan işlemlerin bulunduğu fonksiyondur. Kullanıcıdan bir dosya ismi/yolu
    girmesi beklenir. Bu dosya byte şeklinde okunur ve özütü alınıp, aes ile şifrelenir. Bu şifre
    dosyanın sonuna yazılır. Yazma işlemi yine byte cinsinden olmaktadır.
    :return:
    """
    dosya_ismi = input("Lütfen bir dosya ismi giriniz : ")
    okunan_bytelar = []
    print("Dosya okunuyor, lütfen bekleyiniz ! ")
    with open(dosya_ismi, "rb") as f:
        byte = f.read(1)
        while byte:
            okunan_bytelar.append(byte)
            byte = f.read(1)
    f.close()
    ozut = ozut_hash(okunan_bytelar)
    ozut = bytearray(ozut)
    f = open(dosya_ismi, 'ab+')
    f.write(ozut)
    f.close()
    print("Dosyanın sonuna özüt ile şifrelenen değerler eklendi.\n")

def secim_3():
    """
    Dosyada değişiklik yapılıp yapılmadığının anlaşılması için yazılmış olan test fonksiyonudur.
    Bu fonksiyonun düzgün sonuç verebilmesi için ilk önce aynı dosyanın SEÇİM 2 İLE ÖZÜTÜNÜN ALINIP,
    ŞİFRELENİP DOSYA SONUNA YAZILMASI GEREKMEKTEDİR. AKSİ HALDE DOĞRU SONUÇ ORTAYA ÇIKMAYABİLİR.
    Dosya sonunda bulunan özütle, dosyanın son 16 karakteri hariç alınan metnin özütü karşılaştırılır.
    Eğer aynı ise dosyada değişiklik yapılmamıştır. Ancak farklı ise dosyada değişiklik olmuştur.
    :return:
    """
    print("Lütfen dosyanın 2'nolu seçimle özütünün sona eklendiğinden emin olunuz !")
    dosya_ismi = input("Lütfen bir dosya ismi giriniz : ")
    print("İşlem yapılıyor, lütfen bekleyiniz !'")
    okunan_bytelar = []
    with open(dosya_ismi, "rb") as f:
        byte = f.read(1)
        while byte:
            okunan_bytelar.append(byte)
            byte = f.read(1)
    f.close()
    ozutu_alinacak_veri = okunan_bytelar[:-16]
    dosyadaki_ozut = okunan_bytelar[-16:]

    ozut = ozut_hash(ozutu_alinacak_veri)
    yeni_ozut = []
    for i in range(len(ozut)):
        yeni_ozut.append(bytes([ozut[i]]))

    print("Dosyadaki Özüt  : ", dosyadaki_ozut)
    print("Yeni özüt       : ", yeni_ozut)

    if dosyadaki_ozut == yeni_ozut:
        print("DOSYADA DEĞİŞİKLİK YAPILMAMIŞTIR !\n")
    else:
        print("DOSYA DEĞİŞMİŞTİR !\n")

if __name__ == "__main__":
    """
    Programın daha da güzel anlaşılabilmesi için menü şeklinde yazılan main
    fonksiyonudur.
    """
    while True:
        print("##################################################################")
        print("# Şifreleme programına hoşgeldiniz. Lütfen bir seçenek seçiniz : #")
        print("#      1) AES ve modları test verileriyle çalıstırılsın          #")
        print("#           2) Döküman şifreleme çalıştırılsın                   #")
        print("#   3) Dosyanın değişip, değiştirilmediğinin kontrolü yapılsın   #")
        print("#                        4) Çıkış                                #")
        print("##################################################################")

        secim = int(input())
        print("Seçiminiz : ", secim)

        if secim == 1:
            secim_1()
        elif secim == 2:
            secim_2()
        elif secim == 3:
            secim_3()
        elif secim == 4:
            print("Program sonlandırılıyor ...")
            exit(0)




