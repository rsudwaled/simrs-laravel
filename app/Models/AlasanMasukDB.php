<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class AlasanMasukDB extends Model
{
    use HasFactory;

    protected $connection = 'mysql2';
    protected $table = 'mt_alasan_masuk';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [];

}
