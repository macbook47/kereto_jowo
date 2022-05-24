# support us

support us to make better tools :

Made with ❤ by [aphip uhuy](https://www.linkedin.com/in/faizudin-al-hamawi-a1939349/)

[Buy me a coffee](https://www.buymeacoffee.com/macbook47)

# kereto_jowo
This tools used to book ticket smartly
This program is secret software: you cant redistribute it and/or modify. 
It under the terms of the Himacrot License as published by the Secret Software Society, 
either version 3 of the License, or any later version.


    Usage: python kereto_jowo.py recipe


## with docker

1. clone this repo
2. cd kai_backd
3. build docker
    ```bash
    docker build -t kereto_jowo .
    ```
    
4. access folder with json data
5. run script with docker
    ```bash
    unix    -> docker run --rm -v "$PWD":/data kereto_jowo /data/recipe.txt
    windows -> docker run --rm -v %cd%:/data kereto_jowo /data/recipe.txt
    ```

6. profit

## with katacoda -> free docker playground online

1. open link https://www.katacoda.com/courses/docker/playground
2. create folder projects
    ```bash
    mkdir projects
    ```
3. cd to folder projects
    ```bash
    cd projects
    ```
4. git setting to folder projects
    ```bash
    git init
    ```
5. pull this repo
    ```bash
    git pull https://github.com/macbook47/kereto_jowo/
    ```
6. edit recipe.txt with your data -> kalau gak tau vi, googling dl aja :P
    ```bash
    vi recipe.txt
    ```
    kalau susah pake vi, bisa install dulu nano -> apt-get install nano
    ```bash
    apt-get install nano
    nano recipe.txt
    ```
7. build docker
    ```bash
    docker build -t kereto_jowo .
    ```
8. run docker
    ```bash
    docker run kereto_jowo recipe.txt
    ```
9. profit


## json recipe detail

line 1 is parameter, user and password kai mobile -> 
```json
{
"numretry":"10", -> jumlah rerty
"isusingproxy":"0", -> penggunaan proxy (0 untuk tanpa proxy, 1 untuk menggunakan prox), proxy di set ke localhost:3028
"issetseat":"0", -> jika ingin book no kursi (masih belum bisa ini, di set 0 aja ya)
"email":"aphip_uhuy@ganteng.com", -> user kai mobile
"password":"uhuy123", -> password kai mobile
"imei":"CE92ADD6-86DD-4B96-8EA8-2BC0FF51C72A", -> pake ini aja isinya
"version":"27.2", -> pake ini aja isinya
"buildnumber":"60", -> pake ini aja isinya
"devicetoken":"8BE0D0E2514B83F03CE16C02C8EFF4CAAD3CCA2FD25FCA3339C2ECF7277F0660", -> pake ini aja isinya
"platform":"iphone" -> pake ini aja isinya}
```


line 2 is passenger data ->
```json
{
  "address": "Gedung IT BRI Jakarta", -> alamat mu ndes, ojo di isi akhirat yo
  
  "date_return": "2018-03-18", -> your date return -> isi aja kayak dep date
  
  "dep_date": "2018-03-18", -> your depature date -> tgl keberangkatan yyyy-mm-dd
  
  "des": "CN", -> stasiun tujuan -> untuk kode cek aja di web kai
  
  "email": "macbook.47@gmail.com", -> email nanti yg nerima notif
  
  "isreturn": false, -> kalo mau bolak balik
  
  "name": "Jehan Rachmatika", -> nama yg pesen
  
  "num_pax_adult": "2", -> jumlah penumpang dewasa -> menentukan jumlah array di penumpang dewasa
  
  "num_pax_infant": "1", -> jumlah penumang anak -> menentukan jumlah array di penumpang anak, klo 0 gak usah diisi json nya
  
  "org": "GMR", -> stasiun keberangkatan -> untuk kode cek aja di web kai
  
  "passenger": [ -> data penumpang
      {
        "idnum": "3201111101110009",
        "psgtype": "A",
        "name": "harry potter"
      },
      {
        "idnum": "347101010111003",
        "psgtype": "A",
        "name": "marvolo riddle"
      }
  ],
  
  "phone": "085111111110", -> no hape pemesan
  
  "subclass": "X", -> kelas keretanya -> kode bisa di liat di web kai
  
  "subclass_return": "", -> kelas kereta klo pesen bolak balik
  
  "train_no": "16", -> kode kereta nya -> kode bisa di liat di web kai
  
  "train_no_return": 0
  
}
```

line 3 is additional booking data ->

```json
{"adult": "3", -> jumlah penumpang dewasa
"child": 0, -> jumlah penumpang anak
"date": "2019-03-21", -> your depature date -> tgl keberangkatan yyyy-mm-dd
"date_return": "2019-03-21", -> your date return -> isi aja kayak dep date
"des": "BD", -> stasiun tujuan -> untuk kode cek aja di web kai
"des_is_city": false, -> gak usah diganti
"infant": 0, -> jumlah penumpang bayi
"isreturn": false, -> gak usah diganti
"org": "GMR", -> stasiun keberangkatan -> untuk kode cek aja di web kai
"org_is_city": false,
"subclass": "X", -> kelas keretanya -> kode bisa di liat di web kai
"subclass_return": "", -> kelas kereta klo pesen bolak balik
"train_no": "16", -> kode kereta nya -> kode bisa di liat di web kai
"orgname": "GAMBIR ", -> nama stasiun keberangkatan -> untuk nama cek aja di web kai
"destname": "KOTA YOGYAKARTA ", -> nama stasiun tujuan -> untuk nama cek aja di web kai
"seatclass":"all" -> gak usah diganti
}
```



line 4 is seat data -> jumlah aray json sesuai dg penumpang dewasa -> masih ada bug -> coba2 sendiri aja yes :P

```json
{"seat": "9A","wagon_code": "EKS","wagon_no": "3"},{"seat": "9B","wagon_code": "EKS","wagon_no": "3"}
```

