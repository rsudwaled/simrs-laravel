<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Pasien extends Model
{
    use HasFactory;

    protected $fillable = [
        "norm",
        "nomorkartu",
        "nik",
        "nomorkk",
        "nama",
        "jeniskelamin",
        "tanggallahir",
        "nohp",
        "alamat",
        "kodeprop",
        "namaprop",
        "kodedati2",
        "namadati2",
        "kodekec",
        "namakec",
        "kodekel",
        "namakel",
        "rw",
        "rt",
        "status",
    ];
}
