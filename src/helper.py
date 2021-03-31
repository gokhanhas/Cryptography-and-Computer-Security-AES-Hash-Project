# Gökhan Has - 161044067
# CSE470 PROJE



def string_olustur(string, ilk_indeks, son_indeks, mod):
    """
    16 elemana sahip olan string veri tipindeki değişkeni, int veri tipinde
    listeye dönüştürür ve bu listeyi geri döndürür.
    :param string:
    :param ilk_indeks:
    :param son_indeks:
    :param mod:
    :return:
    """
    if son_indeks - ilk_indeks > 16:
        son_indeks = ilk_indeks + 16
    array = []
    if mod == 'CBC':
        array = [0] * 16
    i = ilk_indeks
    j = 0
    while len(array) < son_indeks - ilk_indeks:
        array.append(0)
    while i < son_indeks:
        array[j] = ord(string[i])
        j += 1
        i += 1
    return array


def kontrol_desteksiz_karakter(metin):
    """
    Şifreleme algoritmasını bozan (bazı Türkçe karakterler gibi ğ,ş)
    karakterlerin kontrolü için kullanılır.
    :param metin:
    :return:
    """
    return metin + (16 - (len(metin) % 16)) * chr((16 - (len(metin) % 16)))

