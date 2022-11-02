<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class PenjaminDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'mt_penjamin_bpjs';
    protected $primaryKey = 'kode_penjamin';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [];

    public function kelompok_penjamin()
    {
        return $this->belongsTo(KelompokPenjaminDB::class, 'kode_kelompok', 'kode_kelompok');
    }

    public function kunjungans()
    {
        return $this->hasMany(KunjunganDB::class, 'kode_penjamin', 'kode_penjamin');
    }
}
