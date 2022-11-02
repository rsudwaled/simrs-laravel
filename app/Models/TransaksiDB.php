<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TransaksiDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_nomor_trx';
    public $timestamps = false;

    protected $fillable = [
        'tgl',
        'no_trx_po',
        'no_trx_layanan',
        'no_trx_detail',
        'unit',
    ];
}
