<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Antrian extends Model
{
    use HasFactory;

    protected $fillable = [
        "kodebooking",
        "jenispasien",
        "nomorkartu",
        "nik",
        "nohp",
        "kodepoli",
        "namapoli",
        "pasienbaru",
        "norm",
        "tanggalperiksa",
        "kodedokter",
        "namadokter",
        "jampraktek",
        "jeniskunjungan",
        "nomorreferensi",
        "nomorantrean",
        "angkaantrean",
        "estimasidilayani",
        "sisakuotajkn",
        "kuotajkn",
        "sisakuotanonjkn",
        "kuotanonjkn",
        "keterangan",
        // tambahan
        "nama",
        "kode_kunjungan",
        "kodetransaksi",
        "lokasi",
        "loket",
        "jenisrujukan",
        "nomorrujukan",
        "nomorsuratkontrol",
        "nomorsep",
        "method",
        "status",
        "taskid",
        "user",
        "taskid1",
        "taskid2",
        "taskid3",
    ];

    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'nik', 'nik');
    }
}
