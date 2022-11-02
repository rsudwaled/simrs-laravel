<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TracerDB extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'tc_tracer_header';
    public $timestamps = false;

    protected $fillable = [
        'kode_kunjungan',
        'tgl_tracer',
        'id_status_tracer',
        'cek_tracer',
    ];
}
