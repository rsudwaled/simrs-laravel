<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Antrian extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'jkn_antrian';

    protected $fillable = [
        "kodebooking",
        "kode_kunjungan",
        "nomorkartu",
        "nik",
        "nohp",
        "kodepoli",
        "norm",
        "method",
        "tanggalperiksa",
        "kodedokter",
        "jampraktek",
        "jeniskunjungan",
        "nomorreferensi",
        "nomorsuratkontrol",
        "nomorrujukan",
        "nomorsep",
        "jenispasien",
        "namapoli",
        "pasienbaru",
        "namadokter",
        "nomorantrean",
        "angkaantrean",
        "lantaipendaftaran",
        "lokasi",
        "estimasidilayani",
        "sisakuotajkn",
        "kuotajkn",
        "sisakuotanonjkn",
        "kuotanonjkn",
        "taskid",
        "keterangan",
        "status_api",
        "user",
        "nama",
        "taskid1",
        "taskid2",
        "taskid3",
    ];

    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'nik', 'nik');
    }
}
