<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class LayananDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'ts_layanan_header';
    protected $fillable = [
        'kode_layanan_header',
        'tgl_entry',
        'kode_kunjungan',
        'kode_unit',
        'kode_tipe_transaksi',
        'pic',
        'tagihan_pribadi',
        'tagihan_penjamin',
        'keterangan',
        'status_layanan',
        'total_layanan',
    ];
}
