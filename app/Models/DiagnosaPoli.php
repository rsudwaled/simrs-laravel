<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class DiagnosaPoli extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'di_pasien_diagnosa_frunit';
    protected $primaryKey = 'kode_kunjungan';
    public $incrementing = false;
    protected $keyType = 'string';
}
