<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SuratKontrol extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'jkn_surat_kontrol';
    protected $fillable = [
        "tglTerbitKontrol",
        "tglRencanaKontrol",
        "poliTujuan",
        "namaPoliTujuan",
        "kodeDokter",
        "namaDokter",
        "noSuratKontrol",
        "noSepAsalKontrol",
        "namaJnsKontrol",
        "noKartu",
        "nama",
        "kelamin",
        "tglLahir",
        "user",
    ];
}
