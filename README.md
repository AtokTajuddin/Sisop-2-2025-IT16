# LAPORAN PRAKTIKUM MODUL-2 #
## Praktikum Sistem Operasi Kelompok IT16 ##

| Nama | NRP       |
|-------|-----------|
| Ahmad Syauqi Reza | 5027241085   |
| Mochammad Atha Tajuddin   | 5027241093  |
| Tiara Fatimah Azzahra   | 5027241090  |
---


### Soal_3 ###
 Dalam soal ini praktikan di minta untuk membuat sebuah file bernamakan malware.c yang nanntinya menghasilkan sebuah malware(proses) dengan mengubah namanya serta bersembunyi dalam init dan bekerja dengan daemonisasi dan menginfeksi perangkat(prosesnya).

Kemudian kriteria lainnya yakni 
-Minecrafter merupakan child process dari rodok.exe
-Wannacryptor meng-enkripsi file secara zip karena pada kasus ini kelompok genap
-Fork bombing fitur dalam rodok.exe, memastikan bahwa membuat sebuah hash hexadecimal dengan panjang karakter random sepanjang 64 karakter, serta waktu pembuatan untuk generating random hasnya ialah dalam rentang 3-30 detik.

proses compilingnya -> gcc -o runme malware.c (gunakan file outputnya sebagai runme.exe supaya nantinya memudahkan deleting salinan binary dari runme pada direktori /home/nama-user)

![1t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/c4a8a06fe29690c5fd8a5bb85b46185933575c14/assets/ss_struktur_proses.png)

kondisi struktur proses saat file malware.c dijalankan

![2t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/c4a8a06fe29690c5fd8a5bb85b46185933575c14/assets/ss_direktori_seudah.png)

Struktur direktori setelah proses running dari file runme hasil dari compiling file malware.c

![3t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/c4a8a06fe29690c5fd8a5bb85b46185933575c14/assets/ss_miner_log.png)

Isi random hash dan diletakkan pada file .log

![4t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/c4a8a06fe29690c5fd8a5bb85b46185933575c14/assets/ss_sebelum_kill_rodok.png)

Karena rodok.exe itu merupakan parent process, jadi seharusnya pada saat rodok.exe di-kill maka proses child nya yakni minecrafter akan mati juga.

![5t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/c4a8a06fe29690c5fd8a5bb85b46185933575c14/assets/ss_setelah_kill_rodok_exe.png)

Kondisi setelah rodok.exe di-kill, di mana proses mine-crafter sudah tidak muncul dikarekan mine-crafter merupakan anak proses dari rodok.exe

![6t](https://github.com/AtokTajuddin/Sisop-2-2025-IT16/blob/66d797936324a789c868cf914c2cfda82a6b1f0b/assets/ss_propagation_runme.png)

Pada kasus ini praktikan diminta bahwa salinan dari binary runme untuk diletakkan diseluruh folder /home/nama-user
sehingga file runme tersebut berada di seluruh folder yang ada pada direktori /home/nama-user.

### Soal_4 ###

Pada soal ini, praktikan diminta untuk membuat file bernama debugmon.c yang dapat :

- Melihat proses yang dijalankan oleh user (list)
- Menjalankan daemon mode (daemon)
- Menghentikan proses pemantauan daemon (stop)
- Menggagalkan proses user yang sedang berjalan (fail)
- Mengizinkan user menjalankan proses kembali (revert)
- Mencatat aktivitaas dalam file .log (log)


Untuk proses compilenya menggunakan command 
<pre lang="markdown"> ``` gcc debugmon.c -o debugmon ``` </pre>

![Compiling](assets/4_compile.png)

- Fungsi list

![list](assets/4_list.png)

- Fungsi daemon

![daemon](assets/4_daemon.png)

- Fungsi stop

![stop](assets/4_stop.png)

- Fungsi fail

![fail](assets/4_fail.png)

- Fungsi revert

![revert](assets/4_revert.png)

- Logging activity

![log](assets/4_log.png)




 



