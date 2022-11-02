<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class LayananDetailDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'ts_layanan_detail';
    protected $fillable = [
        'id_layanan_detail',
        'row_id_header',
        'kode_layanan_header',
        'kode_tarif_detail',
        'total_tarif',
        'tagihan_pribadi',
        'tagihan_penjamin',
        'jumlah_layanan',
        'total_layanan',
        'grantotal_layanan',
        'kode_dokter1',
        'tgl_layanan_detail',
        'status_layanan_detail',
        'tgl_layanan_detail_2',
    ];
}
