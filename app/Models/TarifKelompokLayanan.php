<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TarifKelompokLayanan extends Model
{
    use HasFactory;

    protected $fillable = [
        'namatarifkelompok',
        'prefix',
        'grouptarif',
        'groupvclaim',
        'keterangan',
    ];
}
